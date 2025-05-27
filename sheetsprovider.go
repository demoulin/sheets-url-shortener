package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/api/option" // Added for option.WithContext
	"google.golang.org/api/sheets/v4"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type sheetsProvider struct {
	googleSheetsID string
	sheetName      string
}

func (s *sheetsProvider) Query(ctx context.Context) ([][]interface{}, error) {
	tracer := otel.Tracer("url-shortener/sheetsprovider")
	ctx, span := tracer.Start(ctx, "sheetsProvider.Query")
	defer span.End()

	span.SetAttributes(
		attribute.String("google_sheet_id", s.googleSheetsID),
		attribute.String("sheet_name", s.sheetName),
	)

	if s.googleSheetsID == "" {
		err := fmt.Errorf("GOOGLE_SHEET_ID not set")
		span.RecordError(err)
		// span.SetStatus(codes.Error, err.Error()) // Option B for error status
		return nil, err
	}

	// The context passed to NewService is used for authentication and other setup.
	// For tracing individual HTTP calls made by the sheets service, one would typically
	// instrument the http.Client used by the service via option.WithHTTPClient.
	srv, err := sheets.NewService(ctx)
	if err != nil {
		wrappedErr := fmt.Errorf("unable to retrieve Sheets client: %w", err)
		span.RecordError(wrappedErr)
		return nil, wrappedErr
	}

	log.Println("querying sheet") // This log is within the span
	readRange := "A:B"
	if s.sheetName != "" {
		readRange = s.sheetName + "!" + readRange
	}

	// Use the passed-in context (which may have a timeout) for the Do call.
	resp, err := srv.Spreadsheets.Values.Get(s.googleSheetsID, readRange).Do(option.WithContext(ctx))
	if err != nil {
		wrappedErr := fmt.Errorf("unable to retrieve data from sheet: %w", err)
		span.RecordError(wrappedErr)
		return nil, wrappedErr
	}

	span.SetAttributes(attribute.Int("rows_returned", len(resp.Values)))
	log.Printf("queried %d rows", len(resp.Values)) // This log is also within the span
	return resp.Values, nil
}
