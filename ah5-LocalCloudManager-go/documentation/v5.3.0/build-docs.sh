#!/bin/sh
# Build only this 5.3.0 edition; 5.2.2 sources and PDFs are never touched.
set -eu
cd "$(dirname "$0")"
for source in ./*.tex; do
  latexmk -pdf -interaction=nonstopmode -halt-on-error -quiet "$source"
done
latexmk -c -quiet
rm -f ./*.bbl
