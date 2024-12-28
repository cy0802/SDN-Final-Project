run:
	mvn clean install -DSkipTests
	onos-app localhost install! ~/final-project/apps/vrouter/target/vrouter-1.0-SNAPSHOT.oar

rerun:
	onos-app localhost deactivate nycu.sdnnfv.vrouter
	onos-app localhost uninstall nycu.sdnnfv.vrouter
	mvn clean install -DSkipTests
	onos-app localhost install! ~/final-project/apps/vrouter/target/vrouter-1.0-SNAPSHOT.oar