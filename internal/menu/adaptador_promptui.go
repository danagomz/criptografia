package menu

import (
	"errors"

	"github.com/manifoldco/promptui"
)

// PromptUI implementa Prompter con la librería de terceros promptui.
type PromptUI struct{}

// Select muestra un menú navegable con las flechas del teclado.
func (PromptUI) Select(label string, items []string) (int, error) {
	prompt := promptui.Select{Label: label, Items: items, Size: len(items)}
	idx, _, err := prompt.Run()
	return idx, mapError(err)
}

// Ask pide una línea de texto con validación en vivo.
func (PromptUI) Ask(label string, validate func(string) error) (string, error) {
	prompt := promptui.Prompt{Label: label, Validate: validate}
	answer, err := prompt.Run()
	return answer, mapError(err)
}

func mapError(err error) error {
	if errors.Is(err, promptui.ErrInterrupt) || errors.Is(err, promptui.ErrEOF) {
		return ErrAborted
	}
	return err
}
