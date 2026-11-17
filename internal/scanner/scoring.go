package scanner

import (
	"strings"

	"github.com/z1kkky/scaner/internal/check"
	"github.com/z1kkky/scaner/internal/runner"
)

// calculateScore returns an intentionally conservative, heuristic score.
// A caller must establish complete category coverage before calling it.
func calculateScore(results []runner.Result) (*int32, string) {
	penalties := make(map[string]int32)
	for _, result := range results {
		if result.Status != runner.StatusCompleted {
			return nil, ""
		}
		for _, finding := range result.Findings {
			points, known := severityPenalty(finding.Severity)
			if !known {
				return nil, ""
			}
			if points == 0 {
				continue
			}
			key := findingKey(result.Check, finding)
			if previous := penalties[key]; points > previous {
				penalties[key] = points
			}
		}
	}
	var penalty int32
	for _, points := range penalties {
		penalty += points
	}
	score := int32(100) - penalty
	if score < 0 {
		score = 0
	}
	grade := gradeForScore(score)
	return &score, grade
}

func severityPenalty(severity check.Severity) (int32, bool) {
	switch severity {
	case check.SeverityInfo:
		return 0, true
	case check.SeverityLow:
		return 5, true
	case check.SeverityMedium:
		return 10, true
	case check.SeverityHigh:
		return 20, true
	case check.SeverityCritical:
		return 35, true
	default:
		return 0, false
	}
}

func findingKey(category string, finding check.Finding) string {
	identity := strings.TrimSpace(finding.ID)
	if identity == "" {
		identity = strings.TrimSpace(finding.ProbeID)
	}
	if identity == "" {
		identity = strings.TrimSpace(finding.Title)
	}
	return category + "\x00" + identity
}

func gradeForScore(score int32) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	case score >= 50:
		return "E"
	default:
		return "F"
	}
}
