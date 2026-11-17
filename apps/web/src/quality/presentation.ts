// SPDX-License-Identifier: Apache-2.0
import type {QualityRuleDefinition,QualityRuleView,QualityRunView} from "../../../../packages/domain/src/quality-contracts.ts";
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
 if(run.kind==='freshness'){
  const d=rule.definition,b=run.freshness;
  return !Object.hasOwn(run,'range')&&!Object.hasOwn(run,'reference')&&d.kind==='freshness'&&b.maximumAgeSeconds===d.maximumAgeSeconds&&b.maximumFutureSkewSeconds===d.maximumFutureSkewSeconds&&b.comparison==='latest-timestamptz'&&b.clock==='source-statement-start'&&b.invalidTimestampPolicy==='fail'&&b.nullPolicy==='exclude'&&/^[a-f0-9]{64}$/.test(b.freshnessHash)&&(!run.measurement||run.measurement.kind==='freshness'&&run.measurement.freshnessHash===b.freshnessHash);
 }
 if(run.kind==='reference-allowed-values')return !Object.hasOwn(run,'freshness')&&!Object.hasOwn(run,'range')&&rule.definition.kind==='reference-allowed-values'&&run.reference.setId===rule.definition.reference.setId&&(!run.measurement||(run.measurement.kind==='reference-allowed-values'&&run.measurement.referenceBindingHash===run.reference.bindingHash));
 if(run.kind==='uniqueness')return !Object.hasOwn(run,'freshness')&&!Object.hasOwn(run,'range')&&!Object.hasOwn(run,'reference')&&rule.definition.kind==='uniqueness'&&(!run.measurement||run.measurement.kind==='uniqueness');
 if(run.kind==='range'){
  const definition=rule.definition,binding=run.range;
  return !Object.hasOwn(run,'freshness')&&!Object.hasOwn(run,'reference')&&definition.kind==='range'&&!!rangeBounds(binding.minimum,binding.maximum)&&
   binding.minimum===definition.minimum&&binding.maximum===definition.maximum&&binding.comparison==='int64-inclusive'&&binding.nullPolicy==='exclude'&&
   /^[a-f0-9]{64}$/.test(binding.rangeHash)&&(!run.measurement||run.measurement.kind==='range'&&run.measurement.rangeHash===binding.rangeHash);
 }
 return !Object.hasOwn(run,'freshness')&&!Object.hasOwn(run,'range')&&!Object.hasOwn(run,'kind')&&!Object.hasOwn(run,'reference')&&rule.definition.kind==='completeness'&&(!run.measurement||run.measurement.kind==='completeness');
}

/** Read the selected immutable family's threshold; do not reinterpret history
 * using a later head's kind or borrow another family's similarly named field. */
export function qualityThreshold(definition:QualityRuleDefinition):number {
 switch(definition.kind){case 'freshness':throw new Error('Freshness uses duration, not a percentage');case 'completeness':return definition.maximumNullBasisPoints;case 'reference-allowed-values':return definition.maximumInvalidBasisPoints;case 'uniqueness':return definition.maximumDuplicateBasisPoints;case 'range':return definition.maximumOutOfRangeBasisPoints;}
}
export function qualityThresholdKey(kind:QualityRuleDefinition['kind']):'maximumNull'|'maximumInvalid'|'maximumDuplicate'|'maximumOutOfRange'|'maximumAge' {
 return kind==='freshness'?'maximumAge':kind==='completeness'?'maximumNull':kind==='reference-allowed-values'?'maximumInvalid':kind==='range'?'maximumOutOfRange':'maximumDuplicate';
}

/** Bounds stay canonical ASCII decimal strings from input through submission.
 * BigInt compares them exactly; no trim, localized-digit conversion or Number. */
export function canonicalInt64(input:string):string|null {
 if(input.length>20||!/^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$/.test(input))return null;
 const value=BigInt(input);
 return value>=-9223372036854775808n&&value<=9223372036854775807n?input:null;
}
export function rangeBounds(minimum:string,maximum:string):{minimum:string;maximum:string}|null {
 return canonicalInt64(minimum)!==null&&canonicalInt64(maximum)!==null&&BigInt(minimum)<=BigInt(maximum)?{minimum,maximum}:null;
}

/** User-facing whole seconds; localized digits are admitted without rounding. */
export function freshnessSettingsInput(age:string,skew:string):{maximumAgeSeconds:number;maximumFutureSkewSeconds:number}|null {
 const integer=(v:string,max:number)=>{const s=v.trim().replace(/[٠-٩]/g,c=>String(c.charCodeAt(0)-0x660)).replace(/[۰-۹]/g,c=>String(c.charCodeAt(0)-0x6f0));if(!/^(?:0|[1-9][0-9]{0,7})$/.test(s))return null;const n=Number(s);return n<=max?n:null;};
 const a=integer(age,31536000),f=integer(skew,300);return a!==null&&a>=1&&f!==null?{maximumAgeSeconds:a,maximumFutureSkewSeconds:f}:null;
}
/** Exact display only: never converts a microsecond age through Number. */
export function freshnessAgeLabel(value:string):string {
 if(!/^(?:0|-?[1-9][0-9]{0,17})$/.test(value))throw new Error('Invalid exact age');
 const n=BigInt(value),a=n<0n?-n:n;if(a>315537897599999999n)throw new Error('Invalid exact age');
 return (n<0n?'-':'')+String(a/1000000n)+'.'+String(a%1000000n).padStart(6,'0');
}
