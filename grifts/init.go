package grifts

import (
	"github.com/gobuffalo/buffalo"
	"github.com/patrick/awesome_spreadsheet_api/actions"
)

func init() {
	buffalo.Grifts(actions.App())
}
