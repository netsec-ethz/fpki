package db

import "strings"

// string for stmt
func repeatStmt(N int, noOfComponents int) string {
	components := make([]string, noOfComponents)
	for i := 0; i < len(components); i++ {
		components[i] = "?"
	}
	toRepeat := "(" + strings.Join(components, ",") + ")"
	return strings.Repeat(toRepeat+",", N-1) + toRepeat
}

// string for delete stmt
func repeatStmtForDelete(tableName string, N int) string {
	var deleteSB strings.Builder
	queryStr := "DELETE from `" + tableName + "` WHERE `key` IN ("
	deleteSB.WriteString(queryStr)

	isFirst := true
	for i := 0; i < N; i++ {
		if isFirst {
			deleteSB.WriteString("?")
			isFirst = false
		} else {
			deleteSB.WriteString(", ?")
		}
	}

	deleteSB.WriteString(");")
	return deleteSB.String()
}
