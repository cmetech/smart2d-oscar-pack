"""Fabric can return local task data without executing an SSH command."""

from fabric import task


@task
def inspect(c):
    return {"message": "Smart2D Fabric example ran"}
