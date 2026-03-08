package containerruntimeconfig

import (
	"testing"

	apicfgv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	ctrlcommon "github.com/openshift/machine-config-operator/pkg/controller/common"
	"github.com/openshift/machine-config-operator/test/helpers"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAddKubeletCfgAfterBootstrapKubeletCfg(t *testing.T) {
	for _, platform := range []apicfgv1.PlatformType{apicfgv1.AWSPlatformType, apicfgv1.NonePlatformType, "unrecognized"} {
		t.Run(string(platform), func(t *testing.T) {
			f := newFixture(t)
			f.newController()

			cc := newControllerConfig(ctrlcommon.ControllerConfigName, platform)
			pools := []*mcfgv1.MachineConfigPool{
				helpers.NewMachineConfigPool("master", nil, helpers.MasterSelector, "v0"),
			}
			// ctrcfg for bootstrap mode
			ctrcfg := newContainerRuntimeConfig("log-level", &mcfgv1.ContainerRuntimeConfiguration{LogLevel: "debug"}, metav1.AddLabelToSelector(&metav1.LabelSelector{}, "pools.operator.machineconfiguration.openshift.io/master", ""))

			f.ccLister = append(f.ccLister, cc)
			f.mcpLister = append(f.mcpLister, pools[0])
			f.mccrLister = append(f.mccrLister, ctrcfg)
			f.objects = append(f.objects, ctrcfg)

			mcs, err := RunContainerRuntimeBootstrap("../../../templates", []*mcfgv1.ContainerRuntimeConfig{ctrcfg}, cc, pools)
			require.NoError(t, err)
			require.Len(t, mcs, 1)

			// add ctrcfg1 after bootstrap
			ctrcfg1 := newContainerRuntimeConfig("log-level-master", &mcfgv1.ContainerRuntimeConfiguration{LogLevel: "debug"}, metav1.AddLabelToSelector(&metav1.LabelSelector{}, "pools.operator.machineconfiguration.openshift.io/master", ""))

			f.mccrLister = append(f.mccrLister, ctrcfg1)
			f.objects = append(f.objects, ctrcfg1)
			c := f.newController()
			err = c.syncHandler(getKey(ctrcfg1, t))
			if err != nil {
				t.Errorf("syncHandler returned: %v", err)
			}

			// resync ctrcfg and check the managedKey
			c = f.newController()
			err = c.syncHandler(getKey(ctrcfg, t))
			if err != nil {
				t.Errorf("syncHandler returned: %v", err)
			}
			val := ctrcfg.GetAnnotations()[ctrlcommon.MCNameSuffixAnnotationKey]
			require.Equal(t, "", val)
		})
	}
}

func TestRunCRIOCredentialProviderConfigBootstrap(t *testing.T) {
	// Test cloud platforms and None platform with match images specified, which should generate the CRIOCredentialProviderConfig with the expected contents
	platforms := []apicfgv1.PlatformType{
		apicfgv1.AWSPlatformType,
		apicfgv1.GCPPlatformType,
		apicfgv1.AzurePlatformType,
		apicfgv1.NonePlatformType,
	}
	for _, platform := range platforms {
		t.Run(string(platform), func(t *testing.T) {
			cc := newControllerConfig(ctrlcommon.ControllerConfigName, platform)
			pools := []*mcfgv1.MachineConfigPool{
				helpers.NewMachineConfigPool("master", nil, helpers.MasterSelector, "v0"),
				helpers.NewMachineConfigPool("worker", nil, helpers.WorkerSelector, "v0"),
			}

			// Create CRIOCredentialProviderConfig with match images
			criocpconfig := newCrioCredentialProviderConfig(
				ctrlcommon.CRIOCredentialProviderConfigInstanceName,
				[]string{"quay.io", "*.example.com"},
			)

			// Run bootstrap
			mcs, err := RunCRIOCredentialProviderConfigBootstrap("../../../templates", cc, pools, criocpconfig)
			require.NoError(t, err, "RunCRIOCredentialProviderConfigBootstrap failed for platform %s", platform)

			require.Len(t, mcs, len(pools), "Expected one MachineConfig per pool for platform %s", platform)

			verifyOpts := criocpVerifyOptions{
				expectNilContent:   false,
				expectEmptyEntries: false,
			}

			for i, pool := range pools {
				key, err := getManagedKeyCRIOCredentialProvider(pool)
				require.NoError(t, err, "getManagedKeyCRIOCredentialProvider should not error for pool %s", pool.Name)

				verifyCRIOCredentialProviderConfigContents(t, mcs[i], key, criocpconfig, verifyOpts)
			}
		})
	}
}

func TestRunCRIOCredentialProviderConfigBootstrapWithEmptyMatchImages(t *testing.T) {

	platforms := []apicfgv1.PlatformType{
		apicfgv1.AWSPlatformType,
		apicfgv1.GCPPlatformType,
		apicfgv1.AzurePlatformType,
	}

	for _, platform := range platforms {
		t.Run("with_empty_match_images", func(t *testing.T) {
			cc := newControllerConfig(ctrlcommon.ControllerConfigName, platform)
			pools := []*mcfgv1.MachineConfigPool{
				helpers.NewMachineConfigPool("master", nil, helpers.MasterSelector, "v0"),
				helpers.NewMachineConfigPool("worker", nil, helpers.WorkerSelector, "v0"),
			}

			// Create CRIOCredentialProviderConfig with empty match images (spec: {})
			criocpconfig := newCrioCredentialProviderConfig(
				ctrlcommon.CRIOCredentialProviderConfigInstanceName,
				[]string{},
			)

			// Run bootstrap
			mcs, err := RunCRIOCredentialProviderConfigBootstrap("../../../templates", cc, pools, criocpconfig)
			require.NoError(t, err, "RunCRIOCredentialProviderConfigBootstrap should handle empty match images for platform %s", platform)
			require.Len(t, mcs, len(pools), "Expected one MachineConfig per pool even with empty match images for platform %s", platform)

			verifyOpts := criocpVerifyOptions{
				expectNilContent:   true,
				expectEmptyEntries: true,
			}

			for i, pool := range pools {
				key, err := getManagedKeyCRIOCredentialProvider(pool)
				require.NoError(t, err, "getManagedKeyCRIOCredentialProvider should not error for pool %s", pool.Name)

				verifyCRIOCredentialProviderConfigContents(t, mcs[i], key, criocpconfig, verifyOpts)
			}

		})
	}

}

func TestRunCRIOCredentialProviderConfigBootstrapWithEmptyMatchImagesNonePlatform(t *testing.T) {
	t.Run("with_empty_match_images", func(t *testing.T) {
		cc := newControllerConfig(ctrlcommon.ControllerConfigName, apicfgv1.NonePlatformType)
		pools := []*mcfgv1.MachineConfigPool{
			helpers.NewMachineConfigPool("master", nil, helpers.MasterSelector, "v0"),
			helpers.NewMachineConfigPool("worker", nil, helpers.WorkerSelector, "v0"),
		}

		// Create CRIOCredentialProviderConfig with empty match images (spec: {})
		criocpconfig := newCrioCredentialProviderConfig(
			ctrlcommon.CRIOCredentialProviderConfigInstanceName,
			[]string{},
		)

		// Run bootstrap
		mcs, err := RunCRIOCredentialProviderConfigBootstrap("../../../templates", cc, pools, criocpconfig)

		// Should still generate MachineConfigs for generic platform path injection
		require.NoError(t, err, "RunCRIOCredentialProviderConfigBootstrap should handle empty match images")
		require.NotEmpty(t, mcs, "Expected MachineConfigs even with empty match images")

		verifyOpts := criocpVerifyOptions{
			expectNilContent:   false,
			expectEmptyEntries: true,
		}

		for i, pool := range pools {
			key, err := getManagedKeyCRIOCredentialProvider(pool)
			require.NoError(t, err, "getManagedKeyCRIOCredentialProvider should not error for pool %s", pool.Name)

			verifyCRIOCredentialProviderConfigContents(t, mcs[i], key, criocpconfig, verifyOpts)
		}
	})
}
