#!/bin/bash

# SOC Automation Dashboard - Comprehensive Test Suite

echo "================================================"
echo " SOC Automation Dashboard - Test Suite"
echo "================================================"
echo ""

cd "$(dirname "$0")"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    TEST_NAME=$1
    COMMAND=$2
    
    echo -n "Testing $TEST_NAME... "
    
    if eval "$COMMAND" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Check prerequisites
echo "1. Checking Prerequisites"
echo "------------------------"
run_test "Python 3" "python3 --version"
run_test "pip" "pip --version"
echo ""

# Check project structure
echo "2. Checking Project Structure"
echo "-----------------------------"
run_test "Backend directory" "test -d backend"
run_test "Frontend directory" "test -d frontend"
run_test "Data directory" "test -d data"
run_test "Docs directory" "test -d docs"
run_test "Backend app.py" "test -f backend/app.py"
run_test "Frontend index.html" "test -f frontend/index.html"
run_test "Frontend app.js" "test -f frontend/app.js"
run_test "Frontend style.css" "test -f frontend/style.css"
echo ""

# Check data files
echo "3. Checking Data Files"
echo "----------------------"
run_test "Alerts data" "test -f data/alerts.json"
run_test "Threats data" "test -f data/threats.json"
run_test "Incidents data" "test -f data/incidents.json"
run_test "IOCs data" "test -f data/iocs.json"
echo ""

# Check documentation
echo "4. Checking Documentation"
echo "-------------------------"
run_test "Main README" "test -f README.md"
run_test "API documentation" "test -f docs/API.md"
run_test "Deployment guide" "test -f docs/DEPLOYMENT.md"
run_test "Usage guide" "test -f docs/USAGE.md"
run_test "Project summary" "test -f PROJECT_SUMMARY.md"
echo ""

# Check deployment files
echo "5. Checking Deployment Files"
echo "-----------------------------"
run_test "Dockerfile" "test -f Dockerfile"
run_test "docker-compose.yml" "test -f docker-compose.yml"
run_test "requirements.txt" "test -f backend/requirements.txt"
run_test "start.sh script" "test -f start.sh && test -x start.sh"
echo ""

# Validate JSON files
echo "6. Validating JSON Data"
echo "----------------------"
run_test "Alerts JSON valid" "python3 -m json.tool data/alerts.json"
run_test "Threats JSON valid" "python3 -m json.tool data/threats.json"
run_test "Incidents JSON valid" "python3 -m json.tool data/incidents.json"
run_test "IOCs JSON valid" "python3 -m json.tool data/iocs.json"
echo ""

# Check Python syntax
echo "7. Checking Python Syntax"
echo "-------------------------"
run_test "Backend app.py syntax" "python3 -m py_compile backend/app.py"
echo ""

# Check for security issues in code
echo "8. Security Checks"
echo "------------------"
run_test "No hardcoded secrets" "! grep -r 'password.*=.*[\"'][^\"']*[\"']' backend/ frontend/ 2>/dev/null"
run_test "Debug mode configurable" "grep -q 'FLASK_DEBUG' backend/app.py"
echo ""

# Summary
echo ""
echo "================================================"
echo " Test Results Summary"
echo "================================================"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed! Project is ready for deployment.${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed. Please review the errors above.${NC}"
    exit 1
fi
