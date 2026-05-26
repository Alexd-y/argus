"use client";

type DlqStatsCardsProps = {
  pending: number;
  replayed: number;
  abandoned: number;
  total: number;
  isLoading: boolean;
};

type CardConfig = {
  label: string;
  value: number;
  detail: string;
  accent: string;
};

function DlqStatCard({
  label,
  value,
  detail,
  isLoading,
  accent,
}: {
  label: string;
  value: number;
  detail: string;
  isLoading: boolean;
  accent: string;
}) {
  return (
    <div
      className={`rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4 ${accent}`}
    >
      <div className="text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">
        {label}
      </div>
      {isLoading ? (
        <div className="mt-2 h-8 w-16 animate-pulse rounded bg-[var(--bg-tertiary)]" />
      ) : (
        <div className="mt-2 text-2xl font-bold text-[var(--text-primary)]">
          {value}
        </div>
      )}
      <div className="mt-1 text-xs text-[var(--text-secondary)]">
        {isLoading ? (
          <span className="inline-block h-3 w-24 animate-pulse rounded bg-[var(--bg-tertiary)]" />
        ) : (
          detail
        )}
      </div>
    </div>
  );
}

export function DlqStatsCards({
  pending,
  replayed,
  abandoned,
  total,
  isLoading,
}: DlqStatsCardsProps) {
  const cards: CardConfig[] = [
    {
      label: "Всего",
      value: total,
      detail: "всего записей",
      accent: "border-l-4 border-l-[var(--accent)]",
    },
    {
      label: "В очереди",
      value: pending,
      detail: "ожидают обработки",
      accent: "border-l-4 border-l-amber-500",
    },
    {
      label: "Повторено",
      value: replayed,
      detail: "успешно повторены",
      accent: "border-l-4 border-l-emerald-500",
    },
    {
      label: "Отброшено",
      value: abandoned,
      detail: "окончательно отброшены",
      accent: "border-l-4 border-l-red-500",
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {cards.map((card) => (
        <DlqStatCard
          key={card.label}
          label={card.label}
          value={card.value}
          detail={card.detail}
          isLoading={isLoading}
          accent={card.accent}
        />
      ))}
    </div>
  );
}