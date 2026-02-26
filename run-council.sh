#!/bin/bash
set -e

# === Configuration ===
LANGUAGE="$1"
LANG_SLUG="$2"
MAX_RETRIES=2
CLAUDE_TOOLS="Read,Write,Edit,Bash,WebSearch,WebFetch"

# === Colors and formatting ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# === Helper functions ===

print_header() {
  echo ""
  echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${BLUE}  Language Council: ${LANGUAGE}${NC}"
  echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════${NC}"
  echo ""
}

print_stage() {
  local stage_num="$1"
  local stage_name="$2"
  local stage_desc="$3"
  echo ""
  echo -e "${BOLD}${CYAN}── Stage ${stage_num}: ${stage_name} ──${NC}"
  echo -e "${CYAN}   ${stage_desc}${NC}"
  echo ""
}

print_agent_start() {
  local agent_name="$1"
  echo -e "  ${YELLOW}▶${NC} Starting ${BOLD}${agent_name}${NC}..."
}

print_agent_done() {
  local agent_name="$1"
  local status="$2"
  if [ "$status" = "ok" ]; then
    echo -e "  ${GREEN}✓${NC} ${agent_name} complete"
  else
    echo -e "  ${RED}✗${NC} ${agent_name} FAILED"
  fi
}

print_stage_done() {
  local stage_name="$1"
  echo -e "\n  ${GREEN}${BOLD}Stage complete: ${stage_name}${NC}\n"
}

seconds_to_human() {
  local total_seconds=$1
  local minutes=$((total_seconds / 60))
  local seconds=$((total_seconds % 60))
  if [ "$minutes" -gt 0 ]; then
    echo "${minutes}m ${seconds}s"
  else
    echo "${seconds}s"
  fi
}

# Run a claude agent with retry on failure (including token limit)
run_agent() {
  local prompt_file="$1"
  local agent_name="$2"
  local log_file="logs/${LANG_SLUG}/${agent_name}.log"
  local attempt=0

  mkdir -p "logs/${LANG_SLUG}"

  while [ "$attempt" -le "$MAX_RETRIES" ]; do
    if [ "$attempt" -gt 0 ]; then
      echo -e "  ${YELLOW}↻${NC} Retrying ${agent_name} (attempt $((attempt + 1))/$((MAX_RETRIES + 1)))..."
    fi

    # Build prompt with variable substitution
    local prompt
    prompt="$(sed "s/{{LANGUAGE}}/${LANGUAGE}/g; s/{{LANGUAGE_SLUG}}/${LANG_SLUG}/g" "${prompt_file}")"

    # On retry after token limit, add continuation instructions
    if [ "$attempt" -gt 0 ]; then
      prompt="${prompt}

IMPORTANT: A previous attempt to complete this task ran out of context. The partial output may exist at the expected output path. Please read it if it exists, pick up where it left off, and complete the remaining sections. Do not rewrite sections that are already complete — only fill in what is missing."
    fi

    # Run claude and capture exit code
    if claude -p "${prompt}" --allowedTools "${CLAUDE_TOOLS}" > "${log_file}" 2>&1; then
      return 0
    fi

    attempt=$((attempt + 1))

    # Check if it was a token limit issue
    if grep -qi "token\|context.*length\|context.*limit\|max.*tokens" "${log_file}" 2>/dev/null; then
      echo -e "  ${YELLOW}⚠${NC}  ${agent_name} may have hit token limit — will retry with continuation"
    fi

    if [ "$attempt" -gt "$MAX_RETRIES" ]; then
      echo -e "  ${RED}✗${NC} ${agent_name} failed after $((MAX_RETRIES + 1)) attempts. See ${log_file}"
      return 1
    fi

    sleep 2
  done
}

# Run a stage of parallel agents, with progress tracking
run_parallel_stage() {
  local stage_name="$1"
  shift
  # Remaining args are pairs: prompt_file agent_name prompt_file agent_name ...
  local pids=()
  local names=()
  local start_time=$SECONDS

  while [ $# -gt 0 ]; do
    local prompt_file="$1"
    local agent_name="$2"
    shift 2

    print_agent_start "${agent_name}"
    run_agent "${prompt_file}" "${agent_name}" &
    pids+=($!)
    names+=("${agent_name}")
  done

  # Wait for all and track results
  local all_ok=true
  local failed_agents=()
  for i in "${!pids[@]}"; do
    if ! wait "${pids[$i]}"; then
      print_agent_done "${names[$i]}" "fail"
      all_ok=false
      failed_agents+=("${names[$i]}")
    else
      print_agent_done "${names[$i]}" "ok"
    fi
  done

  local elapsed=$((SECONDS - start_time))
  echo -e "  ${BLUE}⏱${NC}  Elapsed: $(seconds_to_human $elapsed)"

  if [ "$all_ok" = false ]; then
    echo -e "\n  ${RED}${BOLD}WARNING: Failed agents in ${stage_name}: ${failed_agents[*]}${NC}"
    echo -e "  ${YELLOW}Continuing to next stage — check logs for details.${NC}\n"
  fi

  print_stage_done "${stage_name}"
}

# === Validation ===

if [ -z "$LANGUAGE" ] || [ -z "$LANG_SLUG" ]; then
  echo -e "${BOLD}Usage:${NC} ./run-council.sh <LANGUAGE> <LANG_SLUG>"
  echo ""
  echo "Examples:"
  echo "  ./run-council.sh PHP php"
  echo "  ./run-council.sh C c"
  echo "  ./run-council.sh Mojo mojo"
  echo "  ./run-council.sh COBOL cobol"
  exit 1
fi

# Check claude is available
if ! command -v claude &> /dev/null; then
  echo -e "${RED}Error: 'claude' command not found. Install Claude Code first.${NC}"
  exit 1
fi

# === Main execution ===

TOTAL_START=$SECONDS

print_header

# Setup directories
mkdir -p "research/tier1/${LANG_SLUG}/council"
mkdir -p "research/tier1/${LANG_SLUG}/advisors"
mkdir -p "research/tier1/${LANG_SLUG}/cross-reviews"
mkdir -p "logs/${LANG_SLUG}"

# ── Stage 0.5: Researcher ──
print_stage "0.5" "Researcher" "Gathering factual baseline (research brief)"

BRIEF_PATH="research/tier1/${LANG_SLUG}/research-brief.md"
if [ -f "${BRIEF_PATH}" ]; then
  echo -e "  ${GREEN}✓${NC} Research brief already exists at ${BRIEF_PATH}"
  echo -e "  ${YELLOW}  Skipping Stage 0.5. Delete the file to regenerate.${NC}"
  print_stage_done "Researcher"
else
  print_agent_start "researcher"
  stage_start=$SECONDS
  if run_agent "agents/researcher.md" "researcher"; then
    print_agent_done "researcher" "ok"
  else
    print_agent_done "researcher" "fail"
    echo -e "  ${RED}${BOLD}FATAL: Cannot proceed without research brief.${NC}"
    exit 1
  fi
  elapsed=$((SECONDS - stage_start))
  echo -e "  ${BLUE}⏱${NC}  Elapsed: $(seconds_to_human $elapsed)"
  print_stage_done "Researcher"
fi

# ── Stage 1: Council Members ──
print_stage "1" "Council Members" "5 parallel perspectives (apologist, realist, detractor, historian, practitioner)"

run_parallel_stage "Council Members" \
  "agents/council/apologist.md" "apologist" \
  "agents/council/realist.md" "realist" \
  "agents/council/detractor.md" "detractor" \
  "agents/council/historian.md" "historian" \
  "agents/council/practitioner.md" "practitioner"

# ── Stage 2: Advisors ──
print_stage "2" "Advisors" "4 parallel specialist reviews (compiler/runtime, security, pedagogy, systems architecture)"

run_parallel_stage "Advisors" \
  "agents/advisors/compiler-runtime.md" "compiler-runtime" \
  "agents/advisors/security.md" "security" \
  "agents/advisors/pedagogy.md" "pedagogy" \
  "agents/advisors/systems-architecture.md" "systems-architecture"

# ── Stage 3: Consensus ──
print_stage "3" "Consensus" "Synthesizing all inputs into final council report"

print_agent_start "consensus"
stage_start=$SECONDS
if run_agent "agents/consensus.md" "consensus"; then
  print_agent_done "consensus" "ok"
else
  print_agent_done "consensus" "fail"
  echo -e "\n  ${RED}${BOLD}WARNING: Consensus agent failed. Check logs/${LANG_SLUG}/consensus.log${NC}"
fi
elapsed=$((SECONDS - stage_start))
echo -e "  ${BLUE}⏱${NC}  Elapsed: $(seconds_to_human $elapsed)"
print_stage_done "Consensus"

# === Summary ===

TOTAL_ELAPSED=$((SECONDS - TOTAL_START))

echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Council complete: ${LANGUAGE}${NC}"
echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════${NC}"
echo ""

# Verify outputs
echo -e "${BOLD}Output files:${NC}"
EXPECTED_FILES=(
  "research/tier1/${LANG_SLUG}/research-brief.md"
  "research/tier1/${LANG_SLUG}/council/apologist.md"
  "research/tier1/${LANG_SLUG}/council/realist.md"
  "research/tier1/${LANG_SLUG}/council/detractor.md"
  "research/tier1/${LANG_SLUG}/council/historian.md"
  "research/tier1/${LANG_SLUG}/council/practitioner.md"
  "research/tier1/${LANG_SLUG}/advisors/compiler-runtime.md"
  "research/tier1/${LANG_SLUG}/advisors/security.md"
  "research/tier1/${LANG_SLUG}/advisors/pedagogy.md"
  "research/tier1/${LANG_SLUG}/advisors/systems-architecture.md"
  "research/tier1/${LANG_SLUG}/report.md"
)

missing=0
for f in "${EXPECTED_FILES[@]}"; do
  if [ -f "$f" ]; then
    local_size=$(wc -w < "$f" 2>/dev/null || echo "0")
    echo -e "  ${GREEN}✓${NC} ${f} (${local_size} words)"
  else
    echo -e "  ${RED}✗${NC} ${f} — MISSING"
    missing=$((missing + 1))
  fi
done

echo ""
echo -e "${BOLD}Total time:${NC} $(seconds_to_human $TOTAL_ELAPSED)"
echo -e "${BOLD}Logs:${NC} logs/${LANG_SLUG}/"

if [ "$missing" -gt 0 ]; then
  echo ""
  echo -e "${YELLOW}${BOLD}⚠  ${missing} expected file(s) missing. Check logs for errors.${NC}"
  exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}✓ All outputs verified. Report at research/tier1/${LANG_SLUG}/report.md${NC}"
