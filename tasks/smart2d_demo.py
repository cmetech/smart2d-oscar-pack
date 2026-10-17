"""Small local Invoke task for pack authors."""

from invoke import task


@task
def hello(c, name="OSCAR", **_kwargs):
    return {"message": f"Hello, {name}!"}
