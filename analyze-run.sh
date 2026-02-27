#!/bin/bash
# Analyze token usage, cost, and timing from council run JSON logs.
# Usage: ./analyze-run.sh [language_slug]    — analyze one language
#        ./analyze-run.sh                     — analyze all languages with logs

set -e

BOLD='\033[1m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
DIM='\033[2m'
NC='\033[0m'

# Check for jq
if ! command -v jq &> /dev/null; then
  echo "Error: jq is required. Install with: brew install jq"
  exit 1
fi

# Determine which languages to analyze
if [ -n "$1" ]; then
  LANGUAGES=("$1")
else
  LANGUAGES=()
  for dir in logs/*/; do
    if [ -d "$dir" ]; then
      lang=$(basename "$dir")
      LANGUAGES+=("$lang")
    fi
  done
fi

if [ ${#LANGUAGES[@]} -eq 0 ]; then
  echo "No logs found. Run a council first: ./run-council.sh PHP php"
  exit 1
fi

# Agent display order (matches pipeline stages)
AGENTS_ORDERED=(
  researcher
  apologist realist detractor historian practitioner
  compiler-runtime security pedagogy systems-architecture
  consensus
)

STAGE_LABELS=(
  "0.5" "1" "1" "1" "1" "1" "2" "2" "2" "2" "3"
)

# Extract a field from a JSON file, defaulting to 0
jval() {
  jq -r "$1 // 0" "$2" 2>/dev/null || echo "0"
}

# Format seconds to human-readable
fmt_time() {
  local s=$1
  if [ "$s" -ge 60 ]; then
    echo "$((s / 60))m $((s % 60))s"
  else
    echo "${s}s"
  fi
}

# ═══════════════════════════════════════════════════
# Per-language analysis
# ═══════════════════════════════════════════════════

for LANG in "${LANGUAGES[@]}"; do
  LOG_DIR="logs/${LANG}"
  if [ ! -d "$LOG_DIR" ]; then
    echo -e "${RED}No logs for ${LANG}${NC}"
    continue
  fi

  echo ""
  echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${BLUE}  ${LANG^^} — Council Run Analysis${NC}"
  echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Check if JSON files exist (new format) or only text logs (old format)
  json_count=$(ls "${LOG_DIR}"/*.usage.json 2>/dev/null | wc -l)
  if [ "$json_count" -eq 0 ]; then
    echo -e "  ${YELLOW}No .usage.json files found — this run used the old script (text logs only).${NC}"
    echo -e "  ${YELLOW}Rerun with the updated run-council.sh to get detailed usage data.${NC}"
    echo ""

    # Show what we can: file timestamps for timing, output word counts
    echo -e "  ${BOLD}Timing (from file timestamps):${NC}"
    first_ts=""
    last_ts=""
    for agent in "${AGENTS_ORDERED[@]}"; do
      log="${LOG_DIR}/${agent}.log"
      if [ -f "$log" ]; then
        ts=$(stat -c %Y "$log" 2>/dev/null || stat -f %m "$log" 2>/dev/null)
        if [ -z "$first_ts" ] || [ "$ts" -lt "$first_ts" ]; then first_ts=$ts; fi
        if [ -z "$last_ts" ] || [ "$ts" -gt "$last_ts" ]; then last_ts=$ts; fi
      fi
    done
    if [ -n "$first_ts" ] && [ -n "$last_ts" ]; then
      wall=$((last_ts - first_ts))
      echo -e "  Total wall time (approx): ${BOLD}$(fmt_time $wall)${NC}"
    fi

    echo ""
    echo -e "  ${BOLD}Output word counts:${NC}"
    printf "  ${DIM}%-22s %8s${NC}\n" "Agent" "Words"
    printf "  ${DIM}%-22s %8s${NC}\n" "──────────────────────" "────────"
    total_words=0
    for agent in "${AGENTS_ORDERED[@]}"; do
      case $agent in
        researcher)     f="research/tier1/${LANG}/research-brief.md" ;;
        consensus)      f="research/tier1/${LANG}/report.md" ;;
        apologist|realist|detractor|historian|practitioner)
                        f="research/tier1/${LANG}/council/${agent}.md" ;;
        *)              f="research/tier1/${LANG}/advisors/${agent}.md" ;;
      esac
      if [ -f "$f" ]; then
        w=$(wc -w < "$f")
        total_words=$((total_words + w))
        printf "  %-22s %8s\n" "$agent" "${w}"
      fi
    done
    printf "  ${BOLD}%-22s %8s${NC}\n" "TOTAL" "${total_words}"
    echo ""
    continue
  fi

  # ── Full JSON analysis ──

  # Header
  printf "  ${DIM}%-5s %-22s %10s %10s %10s %10s %6s %4s %8s${NC}\n" \
    "Stage" "Agent" "Cost" "Input" "Output" "Cache" "Turns" "Web" "Time"
  printf "  ${DIM}%-5s %-22s %10s %10s %10s %10s %6s %4s %8s${NC}\n" \
    "─────" "──────────────────────" "──────────" "──────────" "──────────" "──────────" "──────" "────" "────────"

  grand_cost=0
  grand_input=0
  grand_output=0
  grand_cache=0
  grand_searches=0
  grand_turns=0
  grand_duration=0
  grand_api_duration=0

  for idx in "${!AGENTS_ORDERED[@]}"; do
    agent="${AGENTS_ORDERED[$idx]}"
    stage="${STAGE_LABELS[$idx]}"
    json="${LOG_DIR}/${agent}.usage.json"

    if [ ! -f "$json" ]; then continue; fi

    cost=$(jval '.total_cost_usd' "$json")
    input_tok=$(jval '.usage.input_tokens' "$json")
    output_tok=$(jval '.usage.output_tokens' "$json")
    cache_read=$(jval '.usage.cache_read_input_tokens' "$json")
    duration_ms=$(jval '.duration_ms' "$json")
    api_ms=$(jval '.duration_api_ms' "$json")
    turns=$(jval '.num_turns' "$json")
    searches=$(jq -r '[.modelUsage // {} | to_entries[] | .value.webSearchRequests // 0] | add // 0' "$json" 2>/dev/null || echo "0")

    dur_sec=$((duration_ms / 1000))

    # Format numbers
    cost_fmt=$(printf "$%.4f" "$cost")
    input_fmt=$(printf "%'d" "$input_tok" 2>/dev/null || echo "$input_tok")
    output_fmt=$(printf "%'d" "$output_tok" 2>/dev/null || echo "$output_tok")
    cache_fmt=$(printf "%'d" "$cache_read" 2>/dev/null || echo "$cache_read")

    printf "  %-5s %-22s %10s %10s %10s %10s %6s %4s %8s\n" \
      "$stage" "$agent" "$cost_fmt" "$input_fmt" "$output_fmt" "$cache_fmt" "$turns" "$searches" "$(fmt_time $dur_sec)"

    # Accumulate totals (using awk for floating point)
    grand_cost=$(echo "$grand_cost $cost" | awk '{printf "%.6f", $1 + $2}')
    grand_input=$((grand_input + input_tok))
    grand_output=$((grand_output + output_tok))
    grand_cache=$((grand_cache + cache_read))
    grand_searches=$((grand_searches + searches))
    grand_turns=$((grand_turns + turns))
    grand_duration=$((grand_duration + duration_ms))
    grand_api_duration=$((grand_api_duration + api_ms))
  done

  # Totals row
  grand_dur_sec=$((grand_duration / 1000))
  grand_api_sec=$((grand_api_duration / 1000))
  grand_cost_fmt=$(printf "$%.4f" "$grand_cost")
  grand_input_fmt=$(printf "%'d" "$grand_input" 2>/dev/null || echo "$grand_input")
  grand_output_fmt=$(printf "%'d" "$grand_output" 2>/dev/null || echo "$grand_output")
  grand_cache_fmt=$(printf "%'d" "$grand_cache" 2>/dev/null || echo "$grand_cache")

  echo ""
  printf "  ${BOLD}%-5s %-22s %10s %10s %10s %10s %6s %4s %8s${NC}\n" \
    "" "TOTAL" "$grand_cost_fmt" "$grand_input_fmt" "$grand_output_fmt" "$grand_cache_fmt" "$grand_turns" "$grand_searches" "$(fmt_time $grand_dur_sec)"

  # ── Breakdown summaries ──
  echo ""
  echo -e "  ${BOLD}Cost breakdown by stage:${NC}"

  for stage_num in "0.5" "1" "2" "3"; do
    stage_cost=0
    stage_input=0
    stage_output=0
    for idx in "${!AGENTS_ORDERED[@]}"; do
      if [ "${STAGE_LABELS[$idx]}" = "$stage_num" ]; then
        agent="${AGENTS_ORDERED[$idx]}"
        json="${LOG_DIR}/${agent}.usage.json"
        if [ -f "$json" ]; then
          c=$(jval '.total_cost_usd' "$json")
          i=$(jval '.usage.input_tokens' "$json")
          o=$(jval '.usage.output_tokens' "$json")
          stage_cost=$(echo "$stage_cost $c" | awk '{printf "%.6f", $1 + $2}')
          stage_input=$((stage_input + i))
          stage_output=$((stage_output + o))
        fi
      fi
    done

    if [ "$(echo "$stage_cost" | awk '{print ($1 > 0)}')" = "1" ]; then
      pct=$(echo "$stage_cost $grand_cost" | awk '{if ($2 > 0) printf "%.0f", ($1/$2)*100; else print "0"}')
      stage_cost_fmt=$(printf "$%.4f" "$stage_cost")
      stage_name=""
      case $stage_num in
        "0.5") stage_name="Researcher" ;;
        "1")   stage_name="Council (×5)" ;;
        "2")   stage_name="Advisors (×4)" ;;
        "3")   stage_name="Consensus" ;;
      esac
      printf "    Stage %-4s %-16s %10s  (%2s%%)\n" "$stage_num" "$stage_name" "$stage_cost_fmt" "$pct"
    fi
  done

  # ── Efficiency metrics ──
  echo ""
  echo -e "  ${BOLD}Efficiency:${NC}"
  cache_pct=$(echo "$grand_cache $grand_input" | awk '{if ($2 > 0) printf "%.0f", ($1/$2)*100; else print "0"}')
  api_pct=$(echo "$grand_api_duration $grand_duration" | awk '{if ($2 > 0) printf "%.0f", ($1/$2)*100; else print "0"}')
  cost_per_word=0
  # Count output words
  total_words=0
  for agent in "${AGENTS_ORDERED[@]}"; do
    case $agent in
      researcher)     f="research/tier1/${LANG}/research-brief.md" ;;
      consensus)      f="research/tier1/${LANG}/report.md" ;;
      apologist|realist|detractor|historian|practitioner)
                      f="research/tier1/${LANG}/council/${agent}.md" ;;
      *)              f="research/tier1/${LANG}/advisors/${agent}.md" ;;
    esac
    if [ -f "$f" ]; then
      w=$(wc -w < "$f")
      total_words=$((total_words + w))
    fi
  done
  if [ "$total_words" -gt 0 ]; then
    cost_per_word=$(echo "$grand_cost $total_words" | awk '{if ($2 > 0) printf "%.6f", $1/$2; else print "0"}')
    cost_per_1k=$(echo "$cost_per_word" | awk '{printf "$%.4f", $1 * 1000}')
  fi

  echo "    Cache hit rate:       ${cache_pct}% of input tokens served from cache"
  echo "    API time / wall time: ${api_pct}%"
  echo "    Output:               ${total_words} words across 11 files"
  if [ "$total_words" -gt 0 ]; then
    echo "    Cost per 1K words:    ${cost_per_1k}"
  fi

  echo ""
done

# ═══════════════════════════════════════════════════
# Cross-language comparison (if multiple)
# ═══════════════════════════════════════════════════

if [ ${#LANGUAGES[@]} -gt 1 ]; then
  echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${BLUE}  Cross-Language Comparison${NC}"
  echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
  echo ""

  printf "  ${DIM}%-12s %10s %10s %10s %10s %6s %8s${NC}\n" \
    "Language" "Cost" "Input" "Output" "Cache" "Turns" "Words"
  printf "  ${DIM}%-12s %10s %10s %10s %10s %6s %8s${NC}\n" \
    "────────────" "──────────" "──────────" "──────────" "──────────" "──────" "────────"

  for LANG in "${LANGUAGES[@]}"; do
    LOG_DIR="logs/${LANG}"
    json_count=$(ls "${LOG_DIR}"/*.usage.json 2>/dev/null | wc -l)
    if [ "$json_count" -eq 0 ]; then
      printf "  %-12s %10s\n" "${LANG}" "(no JSON)"
      continue
    fi

    total_cost=0; total_input=0; total_output=0; total_cache=0; total_turns=0
    for agent in "${AGENTS_ORDERED[@]}"; do
      json="${LOG_DIR}/${agent}.usage.json"
      if [ -f "$json" ]; then
        c=$(jval '.total_cost_usd' "$json")
        i=$(jval '.usage.input_tokens' "$json")
        o=$(jval '.usage.output_tokens' "$json")
        cr=$(jval '.usage.cache_read_input_tokens' "$json")
        t=$(jval '.num_turns' "$json")
        total_cost=$(echo "$total_cost $c" | awk '{printf "%.6f", $1 + $2}')
        total_input=$((total_input + i))
        total_output=$((total_output + o))
        total_cache=$((total_cache + cr))
        total_turns=$((total_turns + t))
      fi
    done

    total_words=0
    for agent in "${AGENTS_ORDERED[@]}"; do
      case $agent in
        researcher)     f="research/tier1/${LANG}/research-brief.md" ;;
        consensus)      f="research/tier1/${LANG}/report.md" ;;
        apologist|realist|detractor|historian|practitioner)
                        f="research/tier1/${LANG}/council/${agent}.md" ;;
        *)              f="research/tier1/${LANG}/advisors/${agent}.md" ;;
      esac
      if [ -f "$f" ]; then
        w=$(wc -w < "$f")
        total_words=$((total_words + w))
      fi
    done

    cost_fmt=$(printf "$%.4f" "$total_cost")
    input_fmt=$(printf "%'d" "$total_input" 2>/dev/null || echo "$total_input")
    output_fmt=$(printf "%'d" "$total_output" 2>/dev/null || echo "$total_output")
    cache_fmt=$(printf "%'d" "$total_cache" 2>/dev/null || echo "$total_cache")

    printf "  %-12s %10s %10s %10s %10s %6s %8s\n" \
      "${LANG}" "$cost_fmt" "$input_fmt" "$output_fmt" "$cache_fmt" "$total_turns" "$total_words"
  done
  echo ""
fi
