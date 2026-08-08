package saml

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

func parseXML(data []byte, maxBytes int) (*etree.Document, error) {
	if maxBytes > 0 && len(data) > maxBytes {
		return nil, newError(
			"SAML_DOCUMENT_TOO_LARGE",
			fmt.Sprintf("SAML document exceeds maximum allowed size (%d bytes)", maxBytes),
		)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return nil, newError("SAML_INVALID_XML", "Failed to parse SAML response XML")
	}
	lower := strings.ToLower(string(trimmed))
	if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<!entity") {
		return nil, newError(
			"SAML_UNSAFE_XML",
			"SAML XML must not contain DTD or entity declarations",
		)
	}
	document := etree.NewDocument()
	document.ReadSettings.Permissive = false
	if err := document.ReadFromBytes(trimmed); err != nil || document.Root() == nil {
		return nil, newError("SAML_INVALID_XML", "Failed to parse SAML response XML", err)
	}
	return document, nil
}

func namespaceMatches(element *etree.Element, namespace string) bool {
	if element == nil {
		return false
	}
	actual := element.NamespaceURI()
	return actual == namespace || actual == ""
}

func directChildren(parent *etree.Element, tag, namespace string) []*etree.Element {
	if parent == nil {
		return nil
	}
	children := make([]*etree.Element, 0)
	for _, child := range parent.ChildElements() {
		if child.Tag == tag && namespaceMatches(child, namespace) {
			children = append(children, child)
		}
	}
	return children
}

func firstDirectChild(parent *etree.Element, tag, namespace string) *etree.Element {
	children := directChildren(parent, tag, namespace)
	if len(children) == 0 {
		return nil
	}
	return children[0]
}

func descendantsByTag(root *etree.Element, tag string) []*etree.Element {
	if root == nil {
		return nil
	}
	var matches []*etree.Element
	var visit func(*etree.Element)
	visit = func(element *etree.Element) {
		if element.Tag == tag {
			matches = append(matches, element)
		}
		for _, child := range element.ChildElements() {
			visit(child)
		}
	}
	visit(root)
	return matches
}

func trimmedText(element *etree.Element) string {
	if element == nil {
		return ""
	}
	return strings.TrimSpace(element.Text())
}
