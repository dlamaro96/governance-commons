import { createContext, useContext } from 'react';
import type { Session } from './types';
export const SessionContext = createContext<Session>(null!);
export const useSession = () => useContext(SessionContext);
export function usePermission(permission: string) { return useSession().permissions.includes(permission); }
