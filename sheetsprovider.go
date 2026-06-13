package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/api/sheets/v4"
)

// queryTimeout bounds a single Sheets API call so a hung request can't wedge
// the cache refresh loop indefinitely.
const queryTimeout = 10 * time.Second

type sheetsProvider struct {
	googleSheetsID string
	sheetName      string
}

func (s *sheetsProvider) Query(ctx context.Context) ([][]interface{}, error) {
	if s.googleSheetsID == "" {
		return nil, fmt.Errorf("GOOGLE_SHEET_ID not set")
	}

	srv, err := sheets.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve Sheets client: %w", err)
	}

	readRange := "A:B"
	if s.sheetName != "" {
		readRange = s.sheetName + "!" + readRange
	}
	slog.Info("querying sheet", "id", s.googleSheetsID, "range", readRange)

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	resp, err := srv.Spreadsheets.Values.Get(s.googleSheetsID, readRange).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve data from sheet: %w", err)
	}
	slog.Info("sheet queried", "rows", len(resp.Values))
	return resp.Values, nil
}
