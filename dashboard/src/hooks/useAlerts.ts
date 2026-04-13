import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { alertsApi } from '../lib/api';
import type { Alert } from '../lib/types';

export function useAlerts(params?: { severity?: string; status?: string; limit?: number }) {
  return useQuery<Alert[]>({
    queryKey: ['alerts', params],
    queryFn: () => alertsApi.list(params) as Promise<Alert[]>,
    refetchInterval: 10000,
  });
}

export function useAlert(id: string) {
  return useQuery<Alert>({
    queryKey: ['alert', id],
    queryFn: () => alertsApi.get(id) as Promise<Alert>,
    enabled: !!id,
  });
}

export function useAlertStats() {
  return useQuery({
    queryKey: ['alert-stats'],
    queryFn: () => alertsApi.stats(),
    refetchInterval: 15000,
  });
}

export function useAcknowledgeAlert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, by }: { id: string; by?: string }) => alertsApi.acknowledge(id, by),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] });
      qc.invalidateQueries({ queryKey: ['alert-stats'] });
    },
  });
}

export function useResolveAlert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, by }: { id: string; by?: string }) => alertsApi.resolve(id, by),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] });
      qc.invalidateQueries({ queryKey: ['alert-stats'] });
    },
  });
}
