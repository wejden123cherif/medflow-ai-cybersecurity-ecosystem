from fastapi import FastAPI, Request, BackgroundTasks
import logging
import json
from graphs.threat_intel_graph import run_threat_intel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("medflow.api")

app = FastAPI(title="MedFlow AI Incident Response API")

def trigger_investigation(alert_data: dict):
    logger.info("Triggering MedFlow investigation from webhook...")
    try:
        # We simulate writing the alert to a file or injecting it into the graph state
        # In a real implementation, we would pass the raw alert directly to the graph
        # For now, we will run the 'live' scenario which pulls the latest alerts from Wazuh
        final_state = run_threat_intel(
            scenario_name="live",
            with_response=True,
            with_approval=False,
            with_execution=True
        )
        logger.info(f"Investigation completed with risk score: {final_state.get('risk_score')}")
    except Exception as e:
        logger.error(f"Error during investigation: {e}")

@app.post("/webhook/wazuh")
async def wazuh_webhook(request: Request, background_tasks: BackgroundTasks):
    try:
        payload = await request.json()
        logger.info(f"Received Wazuh webhook alert: {payload.get('rule', {}).get('id')} - {payload.get('rule', {}).get('description')}")
        
        # Trigger the LangGraph workflow in the background so we return 200 OK to Wazuh immediately
        background_tasks.add_task(trigger_investigation, payload)
        
        return {"status": "success", "message": "Alert received and investigation triggered"}
    except json.JSONDecodeError:
        logger.error("Invalid JSON received from Wazuh")
        return {"status": "error", "message": "Invalid JSON payload"}, 400
    except Exception as e:
        logger.error(f"Failed to process webhook: {e}")
        return {"status": "error", "message": str(e)}, 500

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
