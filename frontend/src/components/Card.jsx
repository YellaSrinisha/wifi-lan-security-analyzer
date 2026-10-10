export default function Card({ title, children, className = '' }) {
  return (
    <div className={`bg-white rounded-lg shadow-sm border border-gray-200 p-6 ${className}`}>
      {title && <h3 className="text-base font-semibold text-gray-900 mb-4">{title}</h3>}
      {children}
    </div>
  );
}
