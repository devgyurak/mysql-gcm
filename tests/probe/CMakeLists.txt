# In-tree build only, exactly like src/CMakeLists.txt: scripts/build-probe.sh copies
# this directory into the build image's server tree as components/probe, where
# CONFIGURE_COMPONENTS() (cmake/component.cmake) picks it up. It is never part of the
# component build and its .so is never shipped — the probe is test scaffolding for
# the nested-function server defect (issue #43).
#
# MYSQL_ADD_COMPONENT takes care of the component compile definitions, the module
# flags and the GenError dependency (mysqld_error.h), so this stays one line and
# cannot drift from how the server builds its own components.
MYSQL_ADD_COMPONENT(probe
  probe.cc
  MODULE_ONLY
)
