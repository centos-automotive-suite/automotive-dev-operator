// Package buildcontract defines the JSON wire types shared by the Build API
// server and its clients. GitSource and status fields reuse the operator's
// api/v1alpha1 types; changes to those CRD types can therefore affect the REST
// schema and must be checked against the OpenAPI contract.
package buildcontract
