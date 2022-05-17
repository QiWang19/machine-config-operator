package containerruntimeconfig

import (
	"context"

	"github.com/golang/glog"
	apicfgv1 "github.com/openshift/api/config/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
)

type ImageDigestMirrorSetV1Alpha1Client struct {
	restClient rest.Interface
}

type ImageDigestMirrorSetInterface interface {
	Create(ctx context.Context, obj *apicfgv1.ImageDigestMirrorSet) (*apicfgv1.ImageDigestMirrorSet, error)
	Update(ctx context.Context, obj *apicfgv1.ImageDigestMirrorSet) (*apicfgv1.ImageDigestMirrorSet, error)
	Delete(ctx context.Context, name string, options *meta_v1.DeleteOptions) error
	Get(ctx context.Context, name string) (*apicfgv1.ImageDigestMirrorSet, error)
}

type imageDigestMirrorSetClient struct {
	client rest.Interface
	ns     string
}

var SchemeGroupVersion = schema.GroupVersion{Group: "config.openshift.io", Version: "v1"}

func (c *ImageDigestMirrorSetV1Alpha1Client) ImageDigestMirrorSets(namespace string) ImageDigestMirrorSetInterface {
	return &imageDigestMirrorSetClient{
		client: c.restClient,
		ns:     namespace,
	}
}

func (c *imageDigestMirrorSetClient) Create(ctx context.Context, obj *apicfgv1.ImageDigestMirrorSet) (*apicfgv1.ImageDigestMirrorSet, error) {
	result := &apicfgv1.ImageDigestMirrorSet{}
	err := c.client.Post().
		Namespace(c.ns).Resource("imagedigestmirrorsets").
		Body(obj).Do(ctx).Into(result)
	return result, err
}

func (c *imageDigestMirrorSetClient) Update(ctx context.Context, obj *apicfgv1.ImageDigestMirrorSet) (*apicfgv1.ImageDigestMirrorSet, error) {
	result := &apicfgv1.ImageDigestMirrorSet{}
	err := c.client.Put().
		Namespace(c.ns).Resource("imagedigestmirrorsets").
		Body(obj).Do(ctx).Into(result)
	return result, err
}

func (c *imageDigestMirrorSetClient) Delete(ctx context.Context, name string, options *meta_v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).Resource("imagedigestmirrorsets").
		Name(name).Body(options).Do(ctx).
		Error()
}

func (c *imageDigestMirrorSetClient) Get(ctx context.Context, name string) (*apicfgv1.ImageDigestMirrorSet, error) {
	result := &apicfgv1.ImageDigestMirrorSet{}
	err := c.client.Get().
		Namespace(c.ns).Resource("imagedigestmirrorsets").
		Name(name).Do(ctx).Into(result)
	return result, err
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&apicfgv1.ImageDigestMirrorSet{},
		&apicfgv1.ImageDigestMirrorSetList{},
	)
	meta_v1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

func NewClient(cfg *rest.Config) (*ImageDigestMirrorSetV1Alpha1Client, error) {
	scheme := runtime.NewScheme()
	SchemeBuilder := runtime.NewSchemeBuilder(addKnownTypes)
	if err := SchemeBuilder.AddToScheme(scheme); err != nil {
		return nil, err
	}
	config := *cfg
	config.GroupVersion = &SchemeGroupVersion
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.NewCodecFactory(scheme)
	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return &ImageDigestMirrorSetV1Alpha1Client{restClient: client}, nil
}

func NewIDMSClient() *ImageDigestMirrorSetV1Alpha1Client {
	config, err := rest.InClusterConfig()
	if err != nil {
		glog.Fatalf("error creating client configuration: %v", err)
	}
	crdclient, err := NewClient(config)
	if err != nil {
		panic(err)
	}
	return crdclient
}
