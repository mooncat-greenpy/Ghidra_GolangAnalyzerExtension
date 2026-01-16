MakeGoEach() {
  local source="sample"
  local goos="$1"
  local goarch="$2"
  local dir="${source}_${goos}_${goarch}"
  local file_name="versions.txt"

  echo "$dir"
  mkdir "$dir"
  while IFS= read -r line; do
    echo "$line"
    env GOOS="$goos" GOARCH="$goarch" "$line" build -ldflags="-s -w" -trimpath -o "${dir}/${dir}_${line}" "${source}.go" || \
      "$line" build -ldflags="-s -w" -o "${dir}/${dir}_${line}" "${source}.go"
  done < "$file_name"
}

MakeGoEach windows amd64
