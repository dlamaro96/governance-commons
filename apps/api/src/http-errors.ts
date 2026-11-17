// SPDX-License-Identifier: Apache-2.0
import type {FastifyError,FastifyReply,FastifyRequest} from 'fastify';
import {Problem} from '../../../packages/authz/src/index.ts';
/** Keep the rate limiter's already-installed Retry-After and quota headers.
 * Its error message is internal; every 429 gets this stable public problem. */
export function apiErrorHandler(error:FastifyError|Problem,req:FastifyRequest,reply:FastifyReply){
 const e=error as FastifyError;
 const status=error instanceof Problem?error.status:e.validation?400:(e.statusCode!==undefined&&e.statusCode>=400&&e.statusCode<500?e.statusCode:500);
 const limited=status===429;
 if(error instanceof Problem&&error.status===503&&error.code==='RELATION_RETRY')reply.header('Retry-After','5');
 if(status===500)req.log.error({code:e.code??'INTERNAL',correlationId:req.id},'Request failed (details redacted)');
 reply.code(status).type('application/problem+json').send({
  type:'about:blank',title:limited?'Too many requests':status>=500?'Service unavailable':'Request rejected',status,
  code:limited?'RATE_LIMITED':error instanceof Problem?error.code:e.validation?'VALIDATION_FAILED':'INTERNAL_ERROR',
  detail:limited?'Too many requests. Please wait, then retry.':error instanceof Problem?error.message:e.validation?'Check the submitted fields.':'The request could not be completed. Use the correlation ID for support.',
  correlationId:req.id,...(!limited&&error instanceof Problem&&error.issues?{issues:error.issues}:{}),
 });
}
