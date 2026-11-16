// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {percentageToBasisPoints,basisPointsToInput,percentageLabel} from '../../apps/web/src/quality/presentation.ts';
test('quality threshold input preserves exact basis points across English and Arabic digits',()=>{
 for(const [text,expected] of [['0',0],['0.01',1],['30',3000],['99.99',9999],['100.00',10000],['٣٠٫٢٥',3025],['۳۰٫۲۵',3025]] as const)assert.equal(percentageToBasisPoints(text),expected);
 for(let value=0;value<=10000;value++)assert.equal(percentageToBasisPoints(basisPointsToInput(value)),value);
});
test('invalid threshold precision, exponent, signs, percentages and overflow never coerce or clamp',()=>{
 for(const value of ['', ' ', '-0','+1','00','01','1e2','0x10','30%','1,2','.1','1.','1.001','100.01','101','Infinity','NaN','١٫٢٫٣'])assert.equal(percentageToBasisPoints(value),null,value);
 for(const value of [-1,10001,0.1,Infinity,NaN])assert.throws(()=>basisPointsToInput(value));
 assert.equal(percentageLabel(3000,'en'),'30%');assert.equal(percentageLabel(3000,'ar'),new Intl.NumberFormat('ar',{style:'percent',maximumFractionDigits:2}).format(0.3));
});
