// SPDX-License-Identifier: Apache-2.0
import postgresql from '../../../connectors/manifests/postgresql.json' with {type:'json'};
import unityCatalog from '../../../connectors/manifests/unity-catalog.json' with {type:'json'};

const manifests = [postgresql, unityCatalog] as const;
export function connectorCapabilities(id: string) {
  const manifest=manifests.find(item=>item.connector_id===id);
  if(!manifest)throw new Error('SOURCE_CONNECTOR_UNSUPPORTED');
  return {metadata:{implemented:manifest.features.metadata.implemented,verification:manifest.features.metadata.verification_level??'NOT_RUN'},
    columnLineage:{implemented:manifest.features.column_lineage.implemented,verification:manifest.features.column_lineage.verification_level??'NOT_RUN'}};
}
export function connectorInventory() {
  return manifests.map(manifest=>({id:manifest.connector_id,name:manifest.connector_id==='postgresql'?'PostgreSQL metadata':'Databricks Unity Catalog metadata',
    implementation:manifest.implementation_status==='partial'?'IN_PROGRESS':'NOT_STARTED',verification:manifest.verification_level??'NOT_RUN',limitations:manifest.limitations}));
}
