"""Local-only fixture service for URL checker benchmarking."""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

app = FastAPI(title="Local offer checker fixture")


@app.get("/test_offer", response_class=HTMLResponse)
async def test_offer(id: int):
    if id == 500:
        raise HTTPException(status_code=500, detail="خطأ داخلي تجريبي")
    if not 1 <= id <= 100:
        raise HTTPException(status_code=404, detail="غير موجود")
    if id % 2 == 0:
        return HTMLResponse(
            f"<html><body><h1>عرض #{id}</h1><p>هذا العرض صالح للقبول وجاهز للتفعيل.</p></body></html>"
        )
    return HTMLResponse(
        f"<html><body><h1>خطأ #{id}</h1><p>انتهى العرض وغير متاح حالياً.</p></body></html>"
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9000)
