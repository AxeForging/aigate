package services

import (
	"fmt"
	"strings"

	"github.com/AxeForging/aigate/domain"
	"github.com/AxeForging/aigate/helpers"
)

type RuleService struct{}

func NewRuleService() *RuleService {
	return &RuleService{}
}

func (s *RuleService) AddDenyRule(cfg *domain.Config, ruleType domain.RuleType, patterns []string) error {
	if len(patterns) == 0 {
		return fmt.Errorf("%w: no patterns provided", helpers.ErrInvalidRule)
	}
	switch ruleType {
	case domain.RuleTypeRead:
		cfg.DenyRead = appendUnique(cfg.DenyRead, patterns)
	case domain.RuleTypeExec:
		cfg.DenyExec = appendUnique(cfg.DenyExec, patterns)
	case domain.RuleTypeNet:
		cfg.AllowNet = appendUnique(cfg.AllowNet, patterns)
	default:
		return fmt.Errorf("%w: unknown rule type %q", helpers.ErrInvalidRule, ruleType)
	}
	return nil
}

func (s *RuleService) RemoveRule(cfg *domain.Config, ruleType domain.RuleType, patterns []string) error {
	if len(patterns) == 0 {
		return fmt.Errorf("%w: no patterns provided", helpers.ErrInvalidRule)
	}
	switch ruleType {
	case domain.RuleTypeRead:
		cfg.DenyRead = removePatterns(cfg.DenyRead, patterns)
	case domain.RuleTypeExec:
		cfg.DenyExec = removePatterns(cfg.DenyExec, patterns)
	case domain.RuleTypeNet:
		cfg.AllowNet = removePatterns(cfg.AllowNet, patterns)
	default:
		return fmt.Errorf("%w: unknown rule type %q", helpers.ErrInvalidRule, ruleType)
	}
	return nil
}

// AddAllowedPaths adds paths to the session scope. Unlike the deny rules,
// allowed_paths is an allowlist: adding entries widens what the sandbox may
// access (and having any entries at all turns scope mode on).
func (s *RuleService) AddAllowedPaths(cfg *domain.Config, paths []string) error {
	if len(paths) == 0 {
		return fmt.Errorf("%w: no paths provided", helpers.ErrInvalidRule)
	}
	cfg.AllowedPaths = appendUnique(cfg.AllowedPaths, paths)
	return nil
}

// RemoveAllowedPaths removes paths from the session scope.
func (s *RuleService) RemoveAllowedPaths(cfg *domain.Config, paths []string) error {
	if len(paths) == 0 {
		return fmt.Errorf("%w: no paths provided", helpers.ErrInvalidRule)
	}
	cfg.AllowedPaths = removePatterns(cfg.AllowedPaths, paths)
	return nil
}

func (s *RuleService) ListRules(cfg *domain.Config) []domain.Rule {
	var rules []domain.Rule
	if len(cfg.DenyRead) > 0 {
		rules = append(rules, domain.Rule{
			Type:     domain.RuleTypeRead,
			Patterns: cfg.DenyRead,
		})
	}
	if len(cfg.DenyExec) > 0 {
		rules = append(rules, domain.Rule{
			Type:     domain.RuleTypeExec,
			Patterns: cfg.DenyExec,
		})
	}
	if len(cfg.AllowNet) > 0 {
		rules = append(rules, domain.Rule{
			Type:     domain.RuleTypeNet,
			Patterns: cfg.AllowNet,
		})
	}
	if len(cfg.AllowedPaths) > 0 {
		rules = append(rules, domain.Rule{
			Type:     domain.RuleTypePath,
			Patterns: cfg.AllowedPaths,
		})
	}
	return rules
}

func (s *RuleService) IsCommandBlocked(cfg *domain.Config, cmd string, args []string) bool {
	for _, denied := range cfg.DenyExec {
		parts := strings.SplitN(denied, " ", 2)
		if len(parts) == 2 {
			// Subcommand rule: "command subcommand"
			if parts[0] == cmd {
				for _, arg := range args {
					if arg == parts[1] {
						return true
					}
				}
			}
		} else {
			// Full command rule
			if denied == cmd {
				return true
			}
		}
	}
	return false
}

func removePatterns(slice, patterns []string) []string {
	toRemove := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		toRemove[p] = true
	}
	var result []string
	for _, v := range slice {
		if !toRemove[v] {
			result = append(result, v)
		}
	}
	return result
}
