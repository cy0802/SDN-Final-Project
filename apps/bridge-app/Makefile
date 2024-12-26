run:
	mvn clean install -DSkipTests
	onos-app localhost install! ~/final-project/apps/bridge-app/target/bridge-app-1.0-SNAPSHOT.oar

rerun:
	onos-app localhost deactivate nycu.sdnnfv.bridge
	onos-app localhost uninstall nycu.sdnnfv.bridge
	mvn clean install -DSkipTests
	onos-app localhost install! ~/final-project/apps/bridge-app/target/bridge-app-1.0-SNAPSHOT.oar