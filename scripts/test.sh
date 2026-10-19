#!/bin/sh
# Checks the corpus images ME7Sum verifies (corpus.tsv checksums=ok) and the
# modified images in testdata/modified. Reports go to testdata/reports/.

cd "$(dirname "$0")/.."
corpus=${CORPUS:-ecu-corpus}
out=testdata/reports
log=$out/err.log

mkdir -p "$out"
trap 'rm -f "$log"' E
: > "$log"

check() {
  echo "$1"
  if [ ! -f "$1" ]; then
    echo "MISSING $1" >> "$log"
    return
  fi
  ./me7sum -r "$out/$2.txt" "$1" | grep -E '(ABORT|WARNING)' >> "$log"
  grep ERROR "$out/$2.txt" >> "$log"
}

if [ -f "$corpus/corpus.tsv" ]; then
  awk -F'\t' 'NR>1 && $8=="ok" {print $1}' "$corpus/corpus.tsv" | while read -r name; do
    part=${name%%-*}
    base=$(printf '%.9s' "$part")
    check "$corpus/images/$base/$name.bin" "$name"
  done
elif [ "$REQUIRE_CORPUS" = 1 ]; then
  echo "no corpus at $corpus and REQUIRE_CORPUS=1 (see BUILD.md)" >&2
  exit 1
else
  echo "no corpus at $corpus, skipping corpus images (see BUILD.md)" >&2
fi

for f in testdata/modified/*.bin; do
  name=${f##*/}
  check "$f" "${name%.bin}"
done

cat "$log"
[ ! -s "$log" ]
