// SPDX-License-Identifier: Apache-2.0
import type {ApprovalDefinition} from '../../../../packages/domain/src/approval-contracts.js';
import type {ClassificationPin} from '../../../../packages/domain/src/classification-contracts.js';

export function pinOf(value:ClassificationPin):ClassificationPin{return {id:value.id,version:value.version,definitionHash:value.definitionHash};}
export function reviewerKeys(definition:ApprovalDefinition):string[]{return [...new Set(definition.stages.flatMap(stage=>stage.assignments))];}
/** Discovery is not authority. These checks prevent malformed local proposals;
 * the service rechecks current membership, assignment authority and visibility. */
export function reviewAssignments(definition:ApprovalDefinition,values:Record<string,string>,activeIds:readonly string[],requesterId:string):Record<string,string>|null{
 const keys=reviewerKeys(definition),active=new Set(activeIds);
 if(!definition.separationOfDuties||!keys.length||Object.keys(values).length!==keys.length)return null;
 const assigned=keys.map(key=>Object.hasOwn(values,key)?values[key]:'');
 if(assigned.some(id=>!id||id===requesterId||!active.has(id))||new Set(assigned).size!==assigned.length)return null;
 return Object.fromEntries(keys.map((key,index)=>[key,assigned[index]]));
}
export function localExpiry(now=Date.now()):string{
 const date=new Date(now+86400000),pad=(n:number)=>String(n).padStart(2,'0');
 return date.getFullYear()+'-'+pad(date.getMonth()+1)+'-'+pad(date.getDate())+'T'+pad(date.getHours())+':'+pad(date.getMinutes());
}
export function proposalExpiry(value:string,now=Date.now()):string|null{
 if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value))return null;
 const date=new Date(value),stamp=date.getTime();
 if(!Number.isFinite(stamp)||stamp<=now||stamp>now+366*86400000)return null;
 const [year,month,day,hour,minute]=value.split(/[-T:]/).map(Number);
 if(date.getFullYear()!==year||date.getMonth()+1!==month||date.getDate()!==day||date.getHours()!==hour||date.getMinutes()!==minute)return null;
 return date.toISOString();
}
