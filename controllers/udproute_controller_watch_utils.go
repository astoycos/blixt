package controllers

import (
	"context"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// mapGatewayToUDPRoutes enqueues reconcilation for all UDPRoutes whenever
// an event occurs on a relevant Gateway.
func (r *UDPRouteReconciler) mapGatewayToUDPRoutes(_ context.Context, obj client.Object) (reqs []reconcile.Request) {
	gateway, ok := obj.(*gatewayv1beta1.Gateway)
	if !ok {
		r.log.Error(fmt.Errorf("invalid type in map func"), "failed to map gateways to udproutes", "expected", "*gatewayv1beta1.Gateway", "received", reflect.TypeOf(obj))
		return
	}

	udproutes := new(gatewayv1alpha2.UDPRouteList)
	if err := r.Client.List(context.Background(), udproutes); err != nil {
		// TODO: https://github.com/kubernetes-sigs/controller-runtime/issues/1996
		r.log.Error(err, "could not enqueue UDPRoutes for Gateway update")
		return
	}

	for _, udproute := range udproutes.Items {
		for _, parentRef := range udproute.Spec.ParentRefs {
			namespace := udproute.Namespace
			if parentRef.Namespace != nil {
				namespace = string(*parentRef.Namespace)
			}
			if parentRef.Name == gatewayv1alpha2.ObjectName(gateway.Name) && namespace == gateway.Namespace {
				reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
					Namespace: udproute.Namespace,
					Name:      udproute.Name,
				}})
			}
		}
	}

	return
}
