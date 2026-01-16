file_name="versions.txt"

while IFS= read -r line; do
  echo "$line"
  go install "golang.org/dl/${line}@latest"
  "${line}" download
done < "$file_name"
