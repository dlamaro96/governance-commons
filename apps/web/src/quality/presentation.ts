// SPDX-License-Identifier: Apache-2.0
import type {QualityRuleView,QualityRunView} from "../../../../packages/domain/src/quality-contracts.js";
/** Decimal percentage admission without floating-point rounding or clamping.
 * Arabic-Indic digits and the Arabic decimal mark are accepted explicitly. */
export function percentageToBasisPoints(input:string):number|null {
 const value=input.trim().replace(/[٠-٩]/g,char=>String(char.charCodeAt(0)-0x660)).replace(/[۰-۹]/g,char=>String(char.charCodeAt(0)-0x6f0)).replaceAll('٫','.');
 if(!/^(?:0|[1-9]\d{0,2})(?:\.\d{1,2})?$/.test(value))return null;
 const [whole,fraction='']=value.split('.'),result=Number(whole)*100+Number(fraction.padEnd(2,'0'));
 return result<=10000?result:null;
}
export function basisPointsToInput(value:number):string {
 if(!Number.isSafeInteger(value)||value<0||value>10000)throw new Error('Invalid quality threshold');
 const fraction=String(value%100).padStart(2,'0').replace(/0+$/,'');
 return String(Math.floor(value/100))+(fraction?'.'+fraction:'');
}
export function percentageLabel(basisPoints:number,locale:'en'|'ar'):string {
 return new Intl.NumberFormat(locale,{style:'percent',maximumFractionDigits:2}).format(basisPoints/10000);
}
/** A blank reference time remains omitted; explicit input must already be UTC
 * milliseconds. No local-time conversion or date rollover is accepted. */
export function referenceTimeInput(input:string,now=Date.now()):string|null {
 if(input==='')return '';
 if(!/^(?!0000)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(input))return null;
 const time=Date.parse(input);
 return Number.isFinite(time)&&time<=now&&new Date(time).toISOString()===input?input:null;
}

/** Display measurements only alongside their exact immutable rule and reference
 * commitment. Current head numbers are intentionally irrelevant to old evidence. */
export function qualityEvidenceMatches(run:QualityRunView,rule:QualityRuleView):boolean {
 if(rule.id!==run.ruleId||rule.version!==run.ruleVersion||rule.definitionHash!==run.ruleHash)return false;
 if(rule.definition.target.columnAssetId!==run.columnAssetId||rule.definition.target.tableAssetId!==run.tableAssetId)return false;
 if(run.kind==='reference-allowed-values')return rule.definition.kind==='reference-allowed-values'&&run.reference.setId===rule.definition.reference.setId&&(!run.measurement||(run.measurement.kind==='reference-allowed-values'&&run.measurement.referenceBindingHash===run.reference.bindingHash));
 return rule.definition.kind==='completeness'&&(!run.measurement||run.measurement.kind==='completeness');
}
