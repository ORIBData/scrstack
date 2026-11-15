package compliance

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
)

// A minimal PDF 1.4 writer for evidence reports: A4 pages, the standard
// Helvetica fonts (not embedded) and text tables. It has no dependencies,
// reads nothing from the network or disk, and writes no timestamp, so the
// same report always produces the same bytes (and the same SHA-256).

const (
	pageWidth  = 595.28
	pageHeight = 841.89
	margin     = 42.0
	textWidth  = pageWidth - 2*margin
	footerY    = 24.0
)

// helvetica holds the Helvetica advance widths (1/1000 em) for ASCII 32-126.
var helvetica = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, // space to /
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, // 0 to ?
	1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, // @ to O
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, // P to _
	333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, // ` to o
	556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, // p to ~
}

// winAnsi converts text to the fonts' WinAnsi encoding; characters it
// cannot show become "?".
func winAnsi(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			out = append(out, ' ')
		case r >= 32 && r <= 126:
			out = append(out, byte(r))
		case r == '…':
			out = append(out, "..."...)
		case r == '–' || r == '—' || r == '−':
			out = append(out, '-')
		case r == '‘' || r == '’':
			out = append(out, '\'')
		case r == '“' || r == '”':
			out = append(out, '"')
		case r == '•':
			out = append(out, 0x95)
		case r >= 0xA0 && r <= 0xFF:
			out = append(out, byte(r))
		default:
			out = append(out, '?')
		}
	}
	return out
}

func charWidth(c byte, size float64, bold bool) float64 {
	w := 556
	if c >= 32 && c <= 126 {
		w = helvetica[c-32]
	}
	f := float64(w) * size / 1000
	if bold {
		// Helvetica-Bold is up to about 10% wider; over-estimating keeps
		// wrapped text inside its box.
		f *= 1.1
	}
	return f
}

func textLen(text []byte, size float64, bold bool) float64 {
	total := 0.0
	for _, c := range text {
		total += charWidth(c, size, bold)
	}
	return total
}

// wrap breaks encoded text into lines no wider than width, splitting words
// that are wider than a line.
func wrap(text []byte, size, width float64, bold bool) [][]byte {
	lines := [][]byte{nil}
	for _, word := range bytes.Fields(text) {
		for len(word) > 0 {
			line := lines[len(lines)-1]
			candidate := word
			if len(line) > 0 {
				candidate = append(append(append([]byte{}, line...), ' '), word...)
			}
			if textLen(candidate, size, bold) <= width {
				lines[len(lines)-1] = candidate
				word = nil
				continue
			}
			if len(line) > 0 {
				lines = append(lines, nil)
				continue
			}
			// A word wider than the line: cut it.
			cut := 1
			for cut < len(word) && textLen(word[:cut+1], size, bold) <= width {
				cut++
			}
			lines[len(lines)-1] = append([]byte{}, word[:cut]...)
			word = word[cut:]
			if len(word) > 0 {
				lines = append(lines, nil)
			}
		}
	}
	return lines
}

func pdfString(text []byte) string {
	var b strings.Builder
	b.WriteByte('(')
	for _, c := range text {
		switch c {
		case '(', ')', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			if c < 32 || c > 126 {
				fmt.Fprintf(&b, "\\%03o", c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte(')')
	return b.String()
}

type pdfDoc struct {
	title string
	pages []*bytes.Buffer
	y     float64
}

func newPDF(title string) *pdfDoc {
	d := &pdfDoc{title: title}
	d.newPage()
	return d
}

func (d *pdfDoc) page() *bytes.Buffer { return d.pages[len(d.pages)-1] }

func (d *pdfDoc) newPage() {
	d.pages = append(d.pages, &bytes.Buffer{})
	d.y = pageHeight - margin
}

// need starts a new page unless height fits above the footer.
func (d *pdfDoc) need(height float64) {
	if d.y-height < margin+footerY {
		d.newPage()
	}
}

func (d *pdfDoc) text(x, y, size float64, bold bool, line []byte) {
	font := "F1"
	if bold {
		font = "F2"
	}
	fmt.Fprintf(d.page(), "BT /%s %.1f Tf %.2f %.2f Td %s Tj ET\n", font, size, x, y, pdfString(line))
}

// paragraph writes wrapped text across the page width.
func (d *pdfDoc) paragraph(s string, size float64, bold bool) {
	leading := size * 1.35
	for _, line := range wrap(winAnsi(s), size, textWidth, bold) {
		d.need(leading)
		d.y -= leading
		d.text(margin, d.y, size, bold, line)
	}
	d.y -= size * 0.5
}

func (d *pdfDoc) heading(s string, size float64) {
	d.need(size*3 + 30) // keep a heading with the first lines below it
	d.y -= size * 0.6
	d.paragraph(s, size, true)
}

// table writes rows under a bold header that repeats on each new page.
// widths are fractions of the page width.
func (d *pdfDoc) table(header []string, widths []float64, rows [][]string) {
	const size, pad = 8.0, 3.0
	leading := size * 1.3
	cells := func(row []string, bold bool) ([][][]byte, float64) {
		out := make([][][]byte, len(widths))
		lines := 1
		for i := range widths {
			value := ""
			if i < len(row) {
				value = row[i]
			}
			out[i] = wrap(winAnsi(value), size, widths[i]*textWidth-2*pad, bold)
			if len(out[i]) > 40 {
				out[i] = append(out[i][:39], []byte("..."))
			}
			lines = max(lines, len(out[i]))
		}
		return out, float64(lines)*leading + 2*pad
	}
	draw := func(row []string, bold bool) {
		content, height := cells(row, bold)
		if bold {
			fmt.Fprintf(d.page(), "0.9 g %.2f %.2f %.2f %.2f re f 0 g\n", margin, d.y-height, textWidth, height)
		}
		x := margin
		for i, lines := range content {
			for j, line := range lines {
				d.text(x+pad, d.y-pad-float64(j+1)*leading+2, size, bold, line)
			}
			x += widths[i] * textWidth
		}
		d.y -= height
		fmt.Fprintf(d.page(), "0.75 G 0.4 w %.2f %.2f m %.2f %.2f l S 0 G\n", margin, d.y, margin+textWidth, d.y)
	}
	_, headerHeight := cells(header, true)
	d.need(headerHeight + 3*leading)
	draw(header, true)
	for _, row := range rows {
		_, height := cells(row, false)
		if d.y-height < margin+footerY {
			d.newPage()
			draw(header, true)
		}
		draw(row, false)
	}
	d.y -= 10
}

// bytes assembles the document, adding a footer to every page.
func (d *pdfDoc) bytes() []byte {
	var out bytes.Buffer
	offsets := []int{}
	object := func(body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	pageCount := len(d.pages)
	kids := make([]string, pageCount)
	for i := range kids {
		kids[i] = fmt.Sprintf("%d 0 R", 6+2*i)
	}
	object("<< /Type /Catalog /Pages 2 0 R >>")
	object(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), pageCount))
	object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	object(fmt.Sprintf("<< /Title %s /Producer (SCRS) >>", pdfString(winAnsi(d.title))))
	for i, content := range d.pages {
		footer := fmt.Sprintf("SCRS evidence report. No compliance verdict.   Page %d of %d", i+1, pageCount)
		fmt.Fprintf(content, "0.4 g BT /F1 7.0 Tf %.2f %.2f Td %s Tj ET 0 g\n", margin, footerY, pdfString(winAnsi(footer)))
		var packed bytes.Buffer
		z := zlib.NewWriter(&packed)
		_, _ = z.Write(content.Bytes())
		_ = z.Close()
		object(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>", pageWidth, pageHeight, 7+2*i))
		object(fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream", packed.Len(), packed.Bytes()))
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	return out.Bytes()
}
