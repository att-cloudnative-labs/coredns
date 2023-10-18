package seekrep

// filteredNamespaceExists checks if namespace exists in this cluster
// according to any `namespace_labels` plugin configuration specified.
// Returns true even for namespaces not exposed by plugin configuration,
// see namespaceExposed.
func (s *SeekrEPHandler) filteredNamespaceExists(namespace string) bool {
	_, err := s.APIConn.GetNamespaceByName(namespace)
	return err == nil
}

// configuredNamespace returns true when the namespace is exposed through the plugin
// `namespaces` configuration.
func (s *SeekrEPHandler) configuredNamespace(namespace string) bool {
	_, ok := s.Namespaces[namespace]
	if len(s.Namespaces) > 0 && !ok {
		return false
	}
	return true
}

func (s *SeekrEPHandler) namespaceExposed(namespace string) bool {
	return s.configuredNamespace(namespace) && s.filteredNamespaceExists(namespace)
}
