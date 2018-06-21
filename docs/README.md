## Compile the docs

Install all dependencies and [Sphinx](http://www.sphinx-doc.org/en/stable/) engine.

Use pip to install dependencies:

```bash
pip install -r requirements.txt
```

Or use pipenv and open a shell with that environment:

```bahs
pipenv install --dev
pipenv shell
```

Call make docs with the format output that you desire:

```bash
# For static HTML website
make html
# For pdf and latex files
make latexpdf
```

## Update the docs from module source files

Use the following command to update the docs files from the source code:

```bash
sphinx-apidoc -fo ./source ..
```

Then you can compile the documentation as described below.
