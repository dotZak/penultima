#!/bin/bash
set -e

# Phase labels
gh label create "phase:1-schema" --color "1B2A4A" --description "Schema design and council formation"
gh label create "phase:2-deliberation" --color "1B2A4A" --description "Internal council reports"
gh label create "phase:3-relevance" --color "1B2A4A" --description "Relevance negotiation"
gh label create "phase:4-cross-review" --color "1B2A4A" --description "Cross-review documents"
gh label create "phase:5-response" --color "1B2A4A" --description "Integrative responses"
gh label create "phase:6-synthesis" --color "1B2A4A" --description "Pattern analysis and design principles"
gh label create "phase:7-design" --color "1B2A4A" --description "Language specification"

# Role labels
gh label create "role:apologist" --color "2E5090"
gh label create "role:realist" --color "2E5090"
gh label create "role:detractor" --color "2E5090"
gh label create "role:historian" --color "2E5090"
gh label create "role:practitioner" --color "2E5090"
gh label create "advisor:compiler-runtime" --color "8DB4D8"
gh label create "advisor:security" --color "8DB4D8"
gh label create "advisor:pedagogy" --color "8DB4D8"
gh label create "advisor:systems-architecture" --color "8DB4D8"
gh label create "council:synthesis" --color "D6E4F0"

# Type labels
gh label create "type:report" --color "0E8A16" --description "A deliverable document"
gh label create "type:review" --color "0E8A16" --description "Advisor or cross-review feedback"
gh label create "type:deadlock" --color "E11D48" --description "Unresolved council disagreement"
gh label create "type:gap" --color "E11D48" --description "Missing analysis identified by synthesis"
gh label create "type:evidence" --color "FBCA04" --description "New data for the evidence repository"
gh label create "type:schema-amendment" --color "FBCA04" --description "Proposed change to the report schema"
gh label create "type:human-feedback" --color "FBCA04" --description "Commentary from human contributors"

# Language labels (pilot)
gh label create "lang:php" --color "777BB4"
gh label create "lang:c" --color "555555"
gh label create "lang:mojo" --color "FF4B00"
gh label create "lang:cobol" --color "005CA5"

# Tier labels
gh label create "tier:1" --color "D4C5F9"
gh label create "tier:2" --color "E2D6F3"
gh label create "tier:3" --color "F0EAF8"