# PhishGuard-X

PhishGuard-X is a hybrid phishing detection system developed in Python that combines machine learning and rule-based analysis to identify malicious URLs. The application provides an interactive Streamlit dashboard where users can analyze URLs or QR codes, view risk assessments, and generate forensic PDF reports.

## Project Objectives

- Detect phishing URLs using a hybrid detection approach.
- Combine machine learning predictions with rule-based analysis.
- Analyze redirect chains and domain information.
- Generate detailed reports to support phishing investigations.
- Provide an interactive dashboard for security analysis.

## Features

- Hybrid phishing detection using Machine Learning and Rule-Based Analysis
- Real-time URL analysis through a Streamlit dashboard
- Random Forest-based phishing prediction
- Redirect chain tracking
- WHOIS domain age lookup
- Trusted domain verification
- Campaign detection using SQLite
- QR code phishing detection
- Risk score calculation and attack classification
- Automated PDF forensic report generation
- Local scan history

## Technology Stack

| Category | Technology |
|----------|------------|
| Programming Language | Python |
| Machine Learning | Scikit-learn (Random Forest) |
| Data Processing | Pandas, NumPy |
| User Interface | Streamlit |
| Database | SQLite |
| Networking | Requests |
| Computer Vision | OpenCV |
| Domain Intelligence | python-whois |
| Report Generation | ReportLab, PyPDF |

## How It Works

1. Validate and sanitize the submitted URL.
2. Extract lexical and structural URL features.
3. Track redirect chains to determine the final destination.
4. Verify trusted domains.
5. Perform WHOIS domain age analysis.
6. Apply rule-based phishing detection.
7. Predict phishing probability using a Random Forest model.
8. Detect similar phishing campaigns using SQLite.
9. Decode and analyze QR codes when provided.
10. Calculate the final risk score and classify the attack.
11. Generate a forensic PDF report and display the results on the dashboard.

## Project Structure

```
PhishGuard-X/
│
├── src/
├── models/
├── assets/
├── README.md
├── requirements.txt
├── LICENSE
└── Project_Report.pdf
```

## Future Improvements

- Integration with external threat intelligence feeds
- Browser extension for real-time protection
- REST API for automated URL scanning
- Support for additional machine learning models

## License

This project is licensed under the MIT License. See the **LICENSE** file for more information.

## Author

**Dipangshu Dey**

