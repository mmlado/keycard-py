from invoke import task


@task
def test(c):
    """Run pytest with coverage"""
    c.run("coverage run -m pytest", pty=True)


@task
def coverage(c):
    c.run("coverage report", pty=True)


@task
def htmlcov(c):
    c.run("coverage html", pty=True)
    print("Open htmlcov/index.html in your browser")


@task
def lint(c):
    """Run flake8 linting"""
    c.run("flake8 keycard tests", pty=True)


@task
def clean(c):
    """Clean artifacts"""
    c.run("rm -rf .pytest_cache htmlcov .coverage", warn=True)
