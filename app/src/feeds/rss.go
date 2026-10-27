package feeds

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"cvewatch/src/model"
)

// feedDoc covers RSS 2.0, RSS 1.0 (RDF) and Atom in one struct.
type feedDoc struct {
	XMLName  xml.Name
	Items    []rssItem   `xml:"channel>item"`
	RDFItems []rssItem   `xml:"item"`
	Entries  []atomEntry `xml:"entry"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	GUID        string `xml:"guid"`
	Description string `xml:"description"`
	Encoded     string `xml:"encoded"` // content:encoded
	PubDate     string `xml:"pubDate"`
	Date        string `xml:"date"` // dc:date
}

type atomEntry struct {
	Title     string     `xml:"title"`
	Links     []atomLink `xml:"link"`
	Summary   string     `xml:"summary"`
	Content   string     `xml:"content"`
	Published string     `xml:"published"`
	Updated   string     `xml:"updated"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

func parseRSS(body []byte, src model.Source, _ time.Time) ([]model.Item, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false // real-world feeds contain stray entities
	dec.CharsetReader = charsetReader
	var doc feedDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode xml: %w", err)
	}
	switch doc.XMLName.Local {
	case "rss", "RDF", "feed":
	default:
		return nil, fmt.Errorf("unrecognized feed root <%s>", doc.XMLName.Local)
	}

	var items []model.Item
	add := func(it model.Item) {
		if it, ok := finish(src.ID, it); ok {
			items = append(items, it)
		}
	}
	for _, e := range append(doc.Items, doc.RDFItems...) {
		add(e.item())
	}
	for _, e := range doc.Entries {
		add(e.item())
	}
	return items, nil
}

func (e rssItem) item() model.Item {
	link := strings.TrimSpace(e.Link)
	if link == "" && strings.HasPrefix(strings.TrimSpace(e.GUID), "http") {
		link = strings.TrimSpace(e.GUID)
	}
	return model.Item{
		Title:     e.Title,
		URL:       link,
		Summary:   firstNonEmpty(e.Description, e.Encoded),
		Published: parseTime(firstNonEmpty(e.PubDate, e.Date)),
	}
}

func (e atomEntry) item() model.Item {
	return model.Item{
		Title:     e.Title,
		URL:       e.link(),
		Summary:   firstNonEmpty(e.Summary, e.Content),
		Published: parseTime(firstNonEmpty(e.Published, e.Updated)),
	}
}

// link prefers the alternate link, which is the one that opens the article.
func (e atomEntry) link() string {
	for _, l := range e.Links {
		if l.Rel == "" || l.Rel == "alternate" {
			return strings.TrimSpace(l.Href)
		}
	}
	if len(e.Links) > 0 {
		return strings.TrimSpace(e.Links[0].Href)
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// charsetReader supports the legacy encodings that still show up in feeds.
func charsetReader(label string, in io.Reader) (io.Reader, error) {
	switch strings.ToLower(label) {
	case "utf-8", "utf8", "us-ascii":
		return in, nil
	case "iso-8859-1", "latin1", "windows-1252":
		raw, err := io.ReadAll(in)
		if err != nil {
			return nil, err
		}
		runes := make([]rune, len(raw))
		for i, b := range raw {
			runes[i] = rune(b)
		}
		return strings.NewReader(string(runes)), nil
	}
	return nil, fmt.Errorf("unsupported charset %q", label)
}
