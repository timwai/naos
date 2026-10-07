interface PlaceholderPageProps {
  title: string;
  description: string;
}

export function PlaceholderPage({
  title,
  description,
}: PlaceholderPageProps) {
  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Stage 13</p>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
      </div>
      <div className="panel empty-panel">
        <strong>尚未接入 mock 数据</strong>
        <p>该页面会在对应后端契约可用后直接接 API。</p>
      </div>
    </section>
  );
}
