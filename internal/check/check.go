// Пакет check описывает, что такое «проверка» и «находка».
//
// Любая проверка сканера (заголовки, SSL, почта, порты...) реализует
// интерфейс Check. Раннер не знает, что именно внутри проверки, —
// он просто вызывает Run() у каждой. Так новые проверки добавляются,
// не трогая остальной код.
package check

import "context"

// Severity — насколько серьёзна проблема.
// Это просто строка, но отдельный тип защищает от опечаток:
// компилятор подскажет, если передать что-то не то.
type Severity string

const (
	SeverityInfo     Severity = "info"     // к сведению, не проблема
	SeverityLow      Severity = "low"      // стоит поправить
	SeverityMedium   Severity = "medium"   // заметная дыра в защите
	SeverityHigh     Severity = "high"     // серьёзный риск
	SeverityCritical Severity = "critical" // чинить немедленно
)

// Finding — одна найденная проблема. Это то, что увидит владелец сайта.
//
// Теги `json:"..."` говорят пакету encoding/json, как назвать поле в JSON.
// Без них поле CheckName превратилось бы в "CheckName", а так будет "check".
type Finding struct {
	ID          string   `json:"id,omitempty"`
	ProbeID     string   `json:"probe_id,omitempty"`
	Probe       string   `json:"probe,omitempty"`
	Location    string   `json:"location,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	CheckName   string   `json:"check"`       // какая проверка нашла
	Title       string   `json:"title"`       // коротко: что не так
	Severity    Severity `json:"severity"`    // насколько серьёзно
	Description string   `json:"description"` // чем грозит, простым языком
	Fix         string   `json:"fix"`         // как исправить
}

// Check — интерфейс проверки.
//
// Интерфейс в Go — это список методов. Любой тип, у которого есть
// такие методы, автоматически «является» Check (писать implements не нужно).
type Check interface {
	// Name — короткое имя проверки, например "headers".
	Name() string

	// Run возвращает находки или ошибку выполнения проверки.
	// Пустой список при nil-ошибке означает, что проблем не найдено.
	//
	// ctx (контекст) несёт дедлайн: когда время вышло, ctx отменяется,
	// и проверка должна прекратить работу. Поэтому ctx нужно передавать
	// во все сетевые вызовы внутри проверки.
	Run(ctx context.Context, domain string) ([]Finding, error)
}

// Options are copied per request; shared checks are never mutated.
type Options struct {
	PagePaths     []string
	DKIMSelectors []string
}
type Configurable interface{ WithOptions(Options) Check }
type ProbeResult struct {
	// CoverageUnknown distinguishes an unknown prerequisite from non-applicability.
	CoverageUnknown bool   `json:"-"`
	ID              string `json:"id"`
	Type            string `json:"type"`
	Status          string `json:"status"`
	Location        string `json:"location"`
	Message         string `json:"message,omitempty"`
}
type Detail struct {
	Findings []Finding
	Probes   []ProbeResult
}
type DetailedCheck interface {
	RunDetailed(context.Context, string) (Detail, error)
}
