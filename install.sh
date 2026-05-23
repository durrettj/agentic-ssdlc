#!/usr/bin/env bash
# ==============================================================================
#                      Aegis-SSDLC Installer Script
# ==============================================================================
# This script deploys the Aegis-SSDLC security toolchain and parameterizes the 
# custom security subagents with correct local pathway environments.
# ==============================================================================

set -eo pipefail

# Text style formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${CYAN}"
echo "    _                 _      _             ____  ____  ____  _      ____ "
echo "   / \   ____  ____  / \  _ / \   _____   / ___|/ ___||  _ \| |    / ___|"
echo "  / _ \ / _  |/ _  |/ /  (_)/ /  / ___/   \___ \\___ \| | | | |   | |    "
echo " / ___ \ (_| | (_| / /_  _ / /_ (__  )     ___) |__) | |_| | |___| |___ "
echo "/_/   \_\___ |\___ \____/ \____/____/     |____/____/|____/|_____|\____|"
echo "        |___/ |___/                                                     "
echo -e "                 - Defending Software Lifecycles -${NC}\n"

# 1. Environment Detection
USER_HOME=$(eval echo "~$USER")
DEFAULT_INSTALL_DIR="${USER_HOME}/aegis-ssdlc"

echo -e "${BLUE}[*] Detecting environment...${NC}"
echo -e "    - Current User: ${BOLD}${USER}${NC}"
echo -e "    - Home Directory: ${BOLD}${USER_HOME}${NC}"

read -r -p "    - Set Installation Directory [Default: ${DEFAULT_INSTALL_DIR}]: " custom_install_dir
INSTALL_DIR="${custom_install_dir:-$DEFAULT_INSTALL_DIR}"
echo -e "    - Target Path set to: ${BOLD}${INSTALL_DIR}${NC}\n"

# 2. Check System Prerequisites
echo -e "${BLUE}[*] Checking prerequisites...${NC}"
MISSING_DEPS=()

for cmd in python3 git gpg ssh; do
    if command -v "$cmd" &>/dev/null; then
        echo -e "    - ${GREEN}✔${NC} $cmd is installed"
    else
        echo -e "    - ${RED}✘${NC} $cmd is missing!"
        MISSING_DEPS+=("$cmd")
    fi
done

# Optional security binaries
echo -e "\n${BLUE}[*] Checking optional security tool dependencies...${NC}"
for sec_tool in semgrep trivy syft gosec govulncheck; do
    if command -v "$sec_tool" &>/dev/null; then
        echo -e "    - ${GREEN}✔${NC} $sec_tool is available in system PATH"
    else
        echo -e "    - ${YELLOW}⚠${NC} $sec_tool is not in system PATH (The scanner will fall back or bypass if unused)"
    fi
done

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo -e "\n${RED}[!] Error: Missing required system dependencies: ${MISSING_DEPS[*]}${NC}"
    echo -e "Please install them before running the setup script again."
    exit 1
fi
echo ""

# 3. Create Directories
echo -e "${BLUE}[*] Creating installation directory layout...${NC}"
mkdir -p "${INSTALL_DIR}/bin"
mkdir -p "${INSTALL_DIR}/templates"
mkdir -p "${INSTALL_DIR}/reports"
echo -e "    - ${GREEN}✔${NC} Layout created under ${INSTALL_DIR}\n"

# 4. Copy Tool Files
echo -e "${BLUE}[*] Deploying scanning utilities and templates...${NC}"
SCRIPT_SRC_DIR="$(dirname "$(readlink -f "$0")")"

if [ -f "${SCRIPT_SRC_DIR}/bin/aegis-sast.py" ] && [ -f "${SCRIPT_SRC_DIR}/bin/aegis-sbom.py" ]; then
    cp "${SCRIPT_SRC_DIR}/bin/aegis-sast.py" "${INSTALL_DIR}/bin/aegis-sast.py"
    cp "${SCRIPT_SRC_DIR}/bin/aegis-sbom.py" "${INSTALL_DIR}/bin/aegis-sbom.py"
    chmod +x "${INSTALL_DIR}/bin/"*.py
    echo -e "    - ${GREEN}✔${NC} Python scan runners copied and marked executable"
else
    echo -e "    - ${RED}✘${NC} Error: Python scan scripts not found in source directory!"
    exit 1
fi

if [ -d "${SCRIPT_SRC_DIR}/templates" ]; then
    cp -r "${SCRIPT_SRC_DIR}/templates/"* "${INSTALL_DIR}/templates/"
    echo -e "    - ${GREEN}✔${NC} Report templates successfully copied"
else
    echo -e "    - ${YELLOW}⚠${NC} Warning: Templates source folder not found!"
fi
echo ""

# 5. Build Active Config File
echo -e "${BLUE}[*] Configuring active parameters...${NC}"
if [ -f "${SCRIPT_SRC_DIR}/config.json.template" ]; then
    sed -e "s|{{AEGIS_DIR}}|${INSTALL_DIR}|g" \
        -e "s|{{PROJECT_PATH}}|${USER_HOME}|g" \
        "${SCRIPT_SRC_DIR}/config.json.template" > "${INSTALL_DIR}/config.json"
    echo -e "    - ${GREEN}✔${NC} Created active configuration: ${INSTALL_DIR}/config.json"
else
    echo -e "    - ${YELLOW}⚠${NC} Warning: config.json.template not found. Skipping active configuration creation."
fi
echo ""

# 6. Template and Deploy Agents
echo -e "${BLUE}[*] Parameterizing security agents...${NC}"
TMP_AGENT_DIR="${INSTALL_DIR}/parameterized_agents"
mkdir -p "$TMP_AGENT_DIR"

if [ -d "${SCRIPT_SRC_DIR}/agents" ]; then
    for agent_file in "${SCRIPT_SRC_DIR}/agents/"*.json; do
        if [ -f "$agent_file" ]; then
            basename_file=$(basename "$agent_file")
            sed -e "s|{{AEGIS_DIR}}|${INSTALL_DIR}|g" \
                -e "s|{{HOME_DIR}}|${USER_HOME}|g" \
                "$agent_file" > "${TMP_AGENT_DIR}/${basename_file}"
        fi
    done
    echo -e "    - ${GREEN}✔${NC} Parameterized agents written to: ${TMP_AGENT_DIR}"
else
    echo -e "    - ${YELLOW}⚠${NC} Warning: Agents template folder not found!"
fi
echo ""

# 7. Antigravity CLI Integration Helper
echo -e "${BLUE}[*] Integrating with Antigravity brain workspace...${NC}"
BRAIN_BASE="${USER_HOME}/.gemini/antigravity-cli/brain"

if [ -d "$BRAIN_BASE" ]; then
    ACTIVE_SESSIONS=($(ls -d "${BRAIN_BASE}/"* 2>/dev/null | grep -E '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' || true))
    if [ ${#ACTIVE_SESSIONS[@]} -gt 0 ]; then
        echo -e "    - Active CLI brain workspace detected."
        echo -e "    - You can load these custom security agents directly into a session!"
        echo -e "\nWould you like to install the agents into your current/latest session? "
        read -r -p "    - Auto-install agents? [y/N]: " auto_install
        
        if [[ "$auto_install" =~ ^[yY](es)?$ ]]; then
            # Find the most recently modified brain directory
            LATEST_SESSION=$(ls -td "${BRAIN_BASE}/"* | head -n 1)
            SESSION_ID=$(basename "$LATEST_SESSION")
            TARGET_AGENT_STORE="${LATEST_SESSION}/.agents/agents"
            
            echo -e "    - Injecting into Session ID: ${CYAN}${SESSION_ID}${NC}"
            
            for p_agent_path in "${TMP_AGENT_DIR}/"*.json; do
                if [ -f "$p_agent_path" ]; then
                    agent_name=$(basename "$p_agent_path" .json)
                    mkdir -p "${TARGET_AGENT_STORE}/${agent_name}"
                    cp "$p_agent_path" "${TARGET_AGENT_STORE}/${agent_name}/agent.json"
                fi
            done
            echo -e "    - ${GREEN}✔${NC} All 6 custom subagents successfully registered in your active workspace!"
        fi
    fi
else
    echo -e "    - Antigravity CLI brain folder not found yet. Agents are saved in your install directory."
fi
echo ""

# 8. Success Report
echo -e "${GREEN}${BOLD}======================================================================${NC}"
echo -e "${GREEN}${BOLD}              AEGIS-SSDLC INSTALLED SUCCESSFULLY!                     ${NC}"
echo -e "${GREEN}${BOLD}======================================================================${NC}"
echo -e "  - Toolsuite Location:   ${BOLD}${INSTALL_DIR}${NC}"
echo -e "  - SAST Scan Utility:    ${BOLD}python3 ${INSTALL_DIR}/bin/aegis-sast.py${NC}"
echo -e "  - SBOM Scan Utility:    ${BOLD}python3 ${INSTALL_DIR}/bin/aegis-sbom.py${NC}"
echo -e "  - Security Templates:   ${BOLD}${INSTALL_DIR}/templates/${NC}"
echo -e "  - Parameterized Agents: ${BOLD}${TMP_AGENT_DIR}/${NC}"
echo -e "  - Configuration:        ${BOLD}${INSTALL_DIR}/config.json${NC}"
echo -e "======================================================================\n"
echo -e "To configure git for automated SAST checks or learn how to run individual scanners,"
echo -e "read the compiled guide at: ${BOLD}${INSTALL_DIR}/README.md${NC}\n"
