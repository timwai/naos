import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import {
  ApiError,
  createDirectory,
  deleteFile,
  downloadFile,
  listDirectory,
  listFileShares,
  moveFile,
} from "../lib/api/client";
import { queryKeys } from "../lib/api/queryKeys";

function errorMessage(error: unknown) {
  if (error instanceof ApiError) {
    return error.body?.message ?? error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "请求失败";
}

function joinPath(parent: string, name: string) {
  return parent === "/" ? `/${name}` : `${parent}/${name}`;
}

function parentPath(path: string) {
  if (path === "/") {
    return "/";
  }
  const parts = path.split("/").filter(Boolean);
  parts.pop();
  return parts.length === 0 ? "/" : `/${parts.join("/")}`;
}

function formatSize(size: number | null | undefined) {
  if (size === null || size === undefined) {
    return "—";
  }
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  if (size < 1024 * 1024 * 1024) {
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  }
  return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

export function FilesPage() {
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [newFolderName, setNewFolderName] = useState("");

  const shares = useQuery({
    queryKey: queryKeys.files.shares(),
    queryFn: listFileShares,
  });

  const requestedShare = params.get("share") ?? "";
  const selectedShare =
    shares.data?.items.find((share) => share.id === requestedShare) ??
    shares.data?.items[0] ??
    null;
  const currentPath = params.get("path") || "/";

  useEffect(() => {
    if (!selectedShare || requestedShare === selectedShare.id) {
      return;
    }
    setParams({ share: selectedShare.id, path: "/" }, { replace: true });
  }, [requestedShare, selectedShare, setParams]);

  const directory = useQuery({
    queryKey: queryKeys.files.directory(selectedShare?.id ?? "", currentPath),
    queryFn: () => listDirectory(selectedShare?.id ?? "", currentPath),
    enabled: Boolean(selectedShare),
  });

  const refreshDirectory = async () => {
    if (!selectedShare) {
      return;
    }
    await queryClient.invalidateQueries({
      queryKey: queryKeys.files.directory(selectedShare.id, currentPath),
    });
  };

  const mkdir = useMutation({
    mutationFn: async () => {
      if (!selectedShare) {
        throw new Error("尚未选择共享");
      }
      const name = newFolderName.trim();
      if (!name || name.includes("/") || name === "." || name === "..") {
        throw new Error("目录名不能包含 /，也不能是 . 或 ..");
      }
      await createDirectory(selectedShare.id, {
        path: joinPath(currentPath, name),
      });
    },
    onSuccess: async () => {
      setNewFolderName("");
      await refreshDirectory();
    },
  });

  const remove = useMutation({
    mutationFn: async (path: string) => {
      if (!selectedShare) {
        throw new Error("尚未选择共享");
      }
      await deleteFile(selectedShare.id, path);
    },
    onSuccess: refreshDirectory,
  });

  const rename = useMutation({
    mutationFn: async ({
      source,
      destination,
    }: {
      source: string;
      destination: string;
    }) => {
      if (!selectedShare) {
        throw new Error("尚未选择共享");
      }
      await moveFile(selectedShare.id, {
        source_path: source,
        destination_path: destination,
      });
    },
    onSuccess: refreshDirectory,
  });

  const download = useMutation({
    mutationFn: async ({ path, name }: { path: string; name: string }) => {
      if (!selectedShare) {
        throw new Error("尚未选择共享");
      }
      const blob = await downloadFile(selectedShare.id, path);
      const url = URL.createObjectURL(blob);
      try {
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = name;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
      } finally {
        URL.revokeObjectURL(url);
      }
    },
  });

  const breadcrumbs = useMemo(() => {
    const parts = currentPath.split("/").filter(Boolean);
    return [
      { label: selectedShare?.name ?? "共享", path: "/" },
      ...parts.map((part, index) => ({
        label: part,
        path: `/${parts.slice(0, index + 1).join("/")}`,
      })),
    ];
  }, [currentPath, selectedShare?.name]);

  const canWrite = selectedShare?.effective_permission === "rw";

  if (shares.isPending) {
    return <div className="center-state">正在加载可访问共享…</div>;
  }

  if (shares.isError) {
    return <div className="error-box">{errorMessage(shares.error)}</div>;
  }

  return (
    <section>
      <div className="page-heading files-heading">
        <div>
          <p className="eyebrow">Files</p>
          <h1>文件</h1>
          <p>通过管理 Session 浏览共享；所有目录与操作权限由后端 ACL 判定。</p>
        </div>
        <label className="files-share-select">
          共享
          <select
            value={selectedShare?.id ?? ""}
            onChange={(event) =>
              setParams({ share: event.target.value, path: "/" })
            }
          >
            {shares.data.items.length === 0 && (
              <option value="">没有可访问共享</option>
            )}
            {shares.data.items.map((share) => (
              <option key={share.id} value={share.id}>
                {share.name} · {share.effective_permission}
              </option>
            ))}
          </select>
        </label>
      </div>

      {!selectedShare ? (
        <div className="panel empty-panel">
          <strong>当前没有可访问共享</strong>
          <p>需要管理员在共享 ACL 中授予当前用户至少只读权限。</p>
        </div>
      ) : (
        <>
          <article className="panel files-toolbar">
            <div className="files-breadcrumbs" aria-label="当前目录">
              {breadcrumbs.map((crumb, index) => (
                <button
                  key={crumb.path}
                  type="button"
                  className="breadcrumb-button"
                  disabled={crumb.path === currentPath}
                  onClick={() =>
                    setParams({ share: selectedShare.id, path: crumb.path })
                  }
                >
                  {index === 0 ? "⌂ " : ""}
                  {crumb.label}
                </button>
              ))}
            </div>

            <div className="files-create-folder">
              <input
                value={newFolderName}
                onChange={(event) => setNewFolderName(event.target.value)}
                placeholder="新目录名称"
                disabled={!canWrite || mkdir.isPending}
              />
              <button
                className="button primary"
                type="button"
                disabled={!canWrite || !newFolderName.trim() || mkdir.isPending}
                onClick={() => mkdir.mutate()}
              >
                {mkdir.isPending ? "创建中…" : "新建目录"}
              </button>
            </div>
          </article>

          {mkdir.isError && (
            <div className="error-box">{errorMessage(mkdir.error)}</div>
          )}
          {remove.isError && (
            <div className="error-box">{errorMessage(remove.error)}</div>
          )}
          {rename.isError && (
            <div className="error-box">{errorMessage(rename.error)}</div>
          )}
          {download.isError && (
            <div className="error-box">{errorMessage(download.error)}</div>
          )}

          <article className="panel files-panel">
            {directory.isPending ? (
              <div className="inline-state">正在读取目录…</div>
            ) : directory.isError ? (
              <div className="error-box">{errorMessage(directory.error)}</div>
            ) : (
              <div className="file-list">
                {currentPath !== "/" && (
                  <button
                    type="button"
                    className="file-row file-row-button"
                    onClick={() =>
                      setParams({
                        share: selectedShare.id,
                        path: parentPath(currentPath),
                      })
                    }
                  >
                    <span className="file-kind">↰</span>
                    <span className="file-name">..</span>
                    <span className="file-meta">上一级</span>
                    <span />
                  </button>
                )}

                {directory.data.entries.length === 0 && currentPath === "/" && (
                  <div className="inline-state">此共享当前为空。</div>
                )}

                {directory.data.entries.map((entry) => {
                  const entryPath = joinPath(currentPath, entry.name);
                  const writable = entry.effective_permission === "rw";
                  return (
                    <div className="file-row" key={entry.name}>
                      <button
                        type="button"
                        className="file-main-action"
                        disabled={entry.kind !== "directory" && entry.kind !== "file"}
                        onClick={() => {
                          if (entry.kind === "directory") {
                            setParams({
                              share: selectedShare.id,
                              path: entryPath,
                            });
                          } else if (entry.kind === "file") {
                            download.mutate({
                              path: entryPath,
                              name: entry.name,
                            });
                          }
                        }}
                      >
                        <span className="file-kind">
                          {entry.kind === "directory"
                            ? "▣"
                            : entry.kind === "file"
                              ? "▤"
                              : entry.kind === "symlink"
                                ? "↗"
                                : "•"}
                        </span>
                        <span className="file-name">{entry.name}</span>
                      </button>

                      <span className="file-meta">
                        {formatSize(entry.size)}
                        {entry.modified_at
                          ? ` · ${new Date(entry.modified_at).toLocaleString()}`
                          : ""}
                      </span>

                      <span className="permission-pill">
                        {entry.effective_permission}
                      </span>

                      <div className="file-actions">
                        <button
                          className="button secondary"
                          type="button"
                          disabled={!writable || rename.isPending}
                          onClick={() => {
                            const next = window.prompt("新名称", entry.name)?.trim();
                            if (
                              !next ||
                              next === entry.name ||
                              next.includes("/") ||
                              next === "." ||
                              next === ".."
                            ) {
                              return;
                            }
                            rename.mutate({
                              source: entryPath,
                              destination: joinPath(currentPath, next),
                            });
                          }}
                        >
                          重命名
                        </button>
                        <button
                          className="button danger"
                          type="button"
                          disabled={!writable || remove.isPending}
                          onClick={() => {
                            if (
                              window.confirm(
                                `确定删除 ${entry.name}？目录会递归删除其内容。`,
                              )
                            ) {
                              remove.mutate(entryPath);
                            }
                          }}
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </article>

          {!canWrite && (
            <div className="inline-state files-readonly-note">
              当前共享根权限为只读；后端仍会对每个子路径重新计算 ACL。
            </div>
          )}
        </>
      )}
    </section>
  );
}
