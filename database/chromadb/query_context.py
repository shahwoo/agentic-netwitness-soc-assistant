from reporting.rag_context import retrieve_reporting_context
print(retrieve_reporting_context({'likely_scenario':'Phishing','severity':{'label':'High'},'classification':'True Positive'})['rag_status'])
