package feeds

import (
	"encoding/json"
	"fmt"
	"time"

	"cvewatch/src/model"
)

// hnResponse is the part of the Algolia search_by_date answer we use.
type hnResponse struct {
	Hits []struct {
		ObjectID  string `json:"objectID"`
		Title     string `json:"title"`
		URL       string `json:"url"`
		StoryText string `json:"story_text"`
		CreatedAt int64  `json:"created_at_i"`
	} `json:"hits"`
}

func parseHN(body []byte, src model.Source, _ time.Time) ([]model.Item, error) {
	var r hnResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	var items []model.Item
	for _, h := range r.Hits {
		url := h.URL
		if url == "" {
			url = "https://news.ycombinator.com/item?id=" + h.ObjectID
		}
		it, ok := finish(src.ID, model.Item{
			Title:     h.Title,
			URL:       url,
			Summary:   h.StoryText,
			Published: time.Unix(h.CreatedAt, 0).UTC(),
		})
		if ok {
			items = append(items, it)
		}
	}
	return items, nil
}
