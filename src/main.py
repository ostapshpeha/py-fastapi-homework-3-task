from fastapi import FastAPI

from routes import movie_router, accounts_router, password_router

app = FastAPI(
    title="Movies homework",
    description="Description of project"
)

api_version_prefix = "/api/v1"

app.include_router(accounts_router, prefix=f"{api_version_prefix}/accounts", tags=["accounts"])
app.include_router(movie_router, prefix=f"{api_version_prefix}/theater", tags=["theater"])
app.include_router(password_router, prefix=f"{api_version_prefix}/password-reset", tags=["passwords"])
