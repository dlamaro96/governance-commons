// SPDX-License-Identifier: Apache-2.0
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
