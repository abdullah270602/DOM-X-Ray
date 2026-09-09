import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { useEffect, useMemo, useRef } from "react";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import type {
  ChannelValues,
  HubObject,
  ModeId,
  PageBusObject,
  RegionObject,
  SceneConnection,
  SceneManifest,
  SceneObject,
} from "../domain/types";

export interface ScenePerformance {
  frameMs: number | null;
  fps: number | null;
  drawCalls: number;
  triangles: number;
  renderer: "GPU" | "SOFTWARE" | null;
}

interface InstrumentSceneProps {
  manifest: SceneManifest;
  channels: ChannelValues;
  mode: ModeId;
  selectedId: string | null;
  isolatedId: string | null;
  playing: boolean;
  onSelect: (id: string) => void;
  onPerformance: (value: ScenePerformance) => void;
}

const palette = {
  paper: "#e9e1d2",
  graphite: "#20251f",
  red: "#d9492f",
  teal: "#2d6571",
  board: "#b8aa8b",
  brass: "#9b772f",
  film: "#f3ede3",
};

function easeOutCubic(value: number) {
  return 1 - Math.pow(1 - value, 3);
}

function CameraRig() {
  const { camera, gl, invalidate, size } = useThree();
  const controlsRef = useRef<OrbitControls | null>(null);

  useEffect(() => {
    const narrow = size.width < 640;
    if (narrow) camera.position.set(13, 10, 34);
    else camera.position.set(9.8, 7.6, 16.5);
    camera.lookAt(0.7, -0.2, 0.5);
    camera.updateProjectionMatrix();

    const controls = new OrbitControls(camera, gl.domElement);
    controls.target.set(0.7, -0.2, 0.5);
    controls.enableDamping = false;
    controls.enablePan = false;
    controls.minDistance = narrow ? 28 : 11;
    controls.maxDistance = narrow ? 44 : 25;
    controls.minPolarAngle = Math.PI * 0.2;
    controls.maxPolarAngle = Math.PI * 0.48;
    controls.minAzimuthAngle = -Math.PI * 0.22;
    controls.maxAzimuthAngle = Math.PI * 0.22;
    const handleChange = () => invalidate();
    controls.addEventListener("change", handleChange);
    controlsRef.current = controls;
    invalidate();
    return () => {
      controls.removeEventListener("change", handleChange);
      controls.dispose();
      controlsRef.current = null;
    };
  }, [camera, gl, invalidate, size.width]);

  return null;
}

function PerformanceProbe({
  onPerformance,
}: {
  onPerformance: (value: ScenePerformance) => void;
}) {
  const samples = useRef<number[]>([]);
  const elapsed = useRef(0);
  const { gl, invalidate } = useThree();

  useFrame((_, delta) => {
    elapsed.current += delta;
    samples.current.push(delta * 1000);
    if (samples.current.length > 120) samples.current.shift();
    if (elapsed.current < 1 || samples.current.length < 2) {
      invalidate();
      return;
    }
    elapsed.current = 0;
    const ordered = [...samples.current].sort((left, right) => left - right);
    const median = ordered[Math.floor(ordered.length / 2)] ?? null;
    const debug = gl.getContext().getExtension("WEBGL_debug_renderer_info");
    const rendererName = debug
      ? String(gl.getContext().getParameter(debug.UNMASKED_RENDERER_WEBGL))
      : String(gl.getContext().getParameter(gl.getContext().RENDERER));
    onPerformance({
      frameMs: median === null ? null : Number(median.toFixed(1)),
      fps: median === null || median === 0 ? null : Math.round(1000 / median),
      drawCalls: gl.info.render.calls,
      triangles: gl.info.render.triangles,
      renderer: /swiftshader|software|llvmpipe/i.test(rendererName) ? "SOFTWARE" : "GPU",
    });
  });
  return null;
}

function useAnimatedTransform(
  targetZ: number,
  targetThickness: number,
  instant: boolean,
) {
  const ref = useRef<THREE.Mesh>(null);
  const { invalidate } = useThree();

  useEffect(() => {
    invalidate();
  }, [invalidate, targetThickness, targetZ]);

  useFrame((_, delta) => {
    const mesh = ref.current;
    if (!mesh) return;
    const factor = instant ? 1 : 1 - Math.exp(-delta * 12);
    mesh.position.z = THREE.MathUtils.lerp(mesh.position.z, targetZ, factor);
    mesh.scale.z = THREE.MathUtils.lerp(
      mesh.scale.z,
      Math.max(0.025, targetThickness),
      factor,
    );
    if (
      Math.abs(mesh.position.z - targetZ) > 0.001 ||
      Math.abs(mesh.scale.z - targetThickness) > 0.001
    ) {
      invalidate();
    }
  });
  return ref;
}

function RegionPlate({
  object,
  channels,
  mode,
  selected,
  isolated,
  instant,
  onSelect,
}: {
  object: RegionObject;
  channels: ChannelValues;
  mode: ModeId;
  selected: boolean;
  isolated: boolean;
  instant: boolean;
  onSelect: (id: string) => void;
}) {
  const mass = object.weight.mass ?? 0;
  const thickness = object.weight.plateThicknessWorld ?? 0.04;
  const targetThickness = 0.04 + channels.weight * thickness;
  const targetZ = channels.structure * object.positionWorld.z + targetThickness / 2;
  const ref = useAnimatedTransform(targetZ, targetThickness, instant);
  const weighted = object.weight.knownTransferredBytes !== null;
  const baseColor =
    mode === "weight" && weighted && mass > 0.7
      ? palette.red
      : object.kind === "aggregate"
        ? "#d6c8ad"
        : object.documentOrder === 0
          ? palette.board
          : palette.film;
  const opacity = isolated ? 0.09 : selected ? 0.98 : mode === "origins" ? 0.44 : 0.84;

  return (
    <mesh
      ref={ref}
      position={[object.positionWorld.x, object.positionWorld.y, 0]}
      scale={[1, 1, 0.04]}
      onClick={(event) => {
        event.stopPropagation();
        onSelect(object.id);
      }}
      castShadow
      receiveShadow
    >
      <boxGeometry args={[object.sizeWorld.width, object.sizeWorld.height, 1]} />
      <meshStandardMaterial
        color={selected ? palette.red : baseColor}
        transparent
        opacity={opacity}
        roughness={mode === "weight" ? 0.6 : 0.86}
        metalness={0.02}
        depthWrite={opacity > 0.5}
      />
      <lineSegments>
        <edgesGeometry args={[new THREE.BoxGeometry(object.sizeWorld.width, object.sizeWorld.height, 1)]} />
        <lineBasicMaterial
          color={selected ? palette.red : palette.graphite}
          transparent
          opacity={isolated ? 0.12 : 0.6}
        />
      </lineSegments>
      {object.documentOrder > 0 && (
        <lineSegments position={[0, 0, 0.515]}>
          <bufferGeometry
            attach="geometry"
            onUpdate={(geometry) => {
              const halfWidth = object.sizeWorld.width * 0.39;
              const halfHeight = object.sizeWorld.height * 0.32;
              const rows = object.sizeWorld.height < 1 ? 1 : 3;
              const points: number[] = [
                -halfWidth, -halfHeight, 0,
                halfWidth, -halfHeight, 0,
                halfWidth, -halfHeight, 0,
                halfWidth, halfHeight, 0,
                halfWidth, halfHeight, 0,
                -halfWidth, halfHeight, 0,
                -halfWidth, halfHeight, 0,
                -halfWidth, -halfHeight, 0,
              ];
              for (let row = 1; row <= rows; row += 1) {
                const y = halfHeight - (row * (halfHeight * 2)) / (rows + 1);
                points.push(-halfWidth * 0.82, y, 0, halfWidth * (row === rows ? 0.22 : 0.7), y, 0);
              }
              geometry.setAttribute("position", new THREE.Float32BufferAttribute(points, 3));
            }}
          />
          <lineBasicMaterial
            color={selected ? palette.paper : palette.graphite}
            transparent
            opacity={isolated ? 0.05 : 0.42}
          />
        </lineSegments>
      )}
    </mesh>
  );
}

function PageBus({
  object,
  channels,
  selected,
  isolated,
  onSelect,
}: {
  object: PageBusObject;
  channels: ChannelValues;
  selected: boolean;
  isolated: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <group
      position={[object.positionWorld.x, object.positionWorld.y, object.positionWorld.z + 0.1]}
      scale={[1, Math.max(0.02, easeOutCubic(channels.origins)), 1]}
      visible={channels.origins > 0.001}
    >
      <mesh
        onClick={(event) => {
          event.stopPropagation();
          onSelect(object.id);
        }}
        castShadow
      >
        <boxGeometry args={[0.18, 5.8, 0.22]} />
        <meshStandardMaterial
          color={selected ? palette.red : palette.brass}
          transparent
          opacity={isolated ? 0.12 : 0.95}
          metalness={0.56}
          roughness={0.42}
        />
      </mesh>
    </group>
  );
}

function Hub({
  object,
  channels,
  selected,
  isolated,
  onSelect,
}: {
  object: HubObject;
  channels: ChannelValues;
  selected: boolean;
  isolated: boolean;
  onSelect: (id: string) => void;
}) {
  const scale = Math.max(0.001, easeOutCubic(channels.origins));
  return (
    <group
      position={[object.positionWorld.x, object.positionWorld.y, object.positionWorld.z + 0.16]}
      scale={[scale, scale, scale]}
      visible={channels.origins > 0.001}
      onClick={(event) => {
        event.stopPropagation();
        onSelect(object.id);
      }}
    >
      <mesh rotation={[Math.PI / 2, 0, 0]} castShadow>
        <cylinderGeometry args={[object.radiusWorld, object.radiusWorld, 0.32, 20]} />
        <meshStandardMaterial
          color={selected ? palette.red : palette.teal}
          transparent
          opacity={isolated ? 0.12 : 0.94}
          metalness={0.48}
          roughness={0.5}
        />
      </mesh>
      <mesh position={[0, 0, 0.19]}>
        <torusGeometry args={[object.radiusWorld * 0.66, 0.045, 8, 24]} />
        <meshStandardMaterial color={palette.paper} metalness={0.2} roughness={0.5} />
      </mesh>
      <mesh position={[0, 0, 0.2]}>
        <cylinderGeometry args={[0.07, 0.07, 0.12, 12]} />
        <meshStandardMaterial color={palette.brass} metalness={0.72} roughness={0.28} />
      </mesh>
    </group>
  );
}

function SceneObjectPart(props: {
  object: SceneObject;
  channels: ChannelValues;
  mode: ModeId;
  selectedId: string | null;
  isolatedId: string | null;
  instant: boolean;
  onSelect: (id: string) => void;
}) {
  const selected = props.selectedId === props.object.id;
  const isolated = props.isolatedId !== null && props.isolatedId !== props.object.id;
  if ("sizeWorld" in props.object) {
    return (
      <RegionPlate
        object={props.object}
        channels={props.channels}
        mode={props.mode}
        selected={selected}
        isolated={isolated}
        instant={props.instant}
        onSelect={props.onSelect}
      />
    );
  }
  if (props.object.kind === "page-bus") {
    return (
      <PageBus
        object={props.object}
        channels={props.channels}
        selected={selected}
        isolated={isolated}
        onSelect={props.onSelect}
      />
    );
  }
  if (props.object.kind === "third-party-hub") return (
    <Hub
      object={props.object}
      channels={props.channels}
      selected={selected}
      isolated={isolated}
      onSelect={props.onSelect}
    />
  );
  return null;
}

function Connection({
  connection,
  objectById,
  channels,
  selected,
  isolated,
  onSelect,
}: {
  connection: SceneConnection;
  objectById: Map<string, SceneObject>;
  channels: ChannelValues;
  selected: boolean;
  isolated: boolean;
  onSelect: (id: string) => void;
}) {
  const line = useMemo(() => {
    const source = objectById.get(connection.sourceObjectId);
    const target = objectById.get(
      connection.targetObjectIds[0] ?? connection.fallbackObjectId ?? "",
    );
    if (!source || !target) return null;
    const sourcePoint = new THREE.Vector3(
      source.positionWorld.x,
      source.positionWorld.y,
      source.positionWorld.z + 0.2,
    );
    let targetPoint = new THREE.Vector3(
      target.positionWorld.x,
      target.positionWorld.y,
      target.positionWorld.z + 0.2,
    );
    if (source.id === target.id) {
      targetPoint = new THREE.Vector3(4.9, source.positionWorld.y * 0.55, 0.6);
    }
    const middle = sourcePoint.clone().lerp(targetPoint, 0.5);
    middle.z += 0.45;
    const curve = new THREE.QuadraticBezierCurve3(sourcePoint, middle, targetPoint);
    const geometry = new THREE.BufferGeometry().setFromPoints(curve.getPoints(20));
    const dashed = connection.visualState !== "solid";
    const material = dashed
      ? new THREE.LineDashedMaterial({
          color: palette.teal,
          dashSize: 0.12,
          gapSize: 0.08,
          transparent: true,
        })
      : new THREE.LineBasicMaterial({ color: palette.teal, transparent: true });
    const object = new THREE.Line(geometry, material);
    if (dashed) object.computeLineDistances();
    return object;
  }, [connection, objectById]);

  useEffect(
    () => () => {
      line?.geometry.dispose();
      if (Array.isArray(line?.material)) line.material.forEach((item) => item.dispose());
      else line?.material.dispose();
    },
    [line],
  );

  if (!line || channels.origins <= 0.001) return null;
  const material = line.material as THREE.LineBasicMaterial;
  material.color.set(selected ? palette.red : palette.teal);
  material.opacity = (isolated ? 0.08 : 0.25 + channels.origins * 0.68) *
    (channels.weight > 0.01 ? 1 : 0.65);
  material.linewidth = Math.max(1, connection.measurement.cableThicknessWorld * 12);
  line.visible = true;
  return (
    <primitive
      object={line}
      onClick={(event: { stopPropagation: () => void }) => {
        event.stopPropagation();
        onSelect(connection.id);
      }}
    />
  );
}

function RegistrationReticle({ manifest, channels }: { manifest: SceneManifest; channels: ChannelValues }) {
  const target = manifest.objects.find(
    (item): item is RegionObject =>
      (item.kind === "region" || item.kind === "aggregate") && item.weight.mass !== null,
  );
  if (!target) return null;
  const markerX = Math.min(5.7, target.positionWorld.x + target.sizeWorld.width / 2 + 0.35);
  return (
    <group scale={0.35 + channels.finding * 0.65} visible={channels.finding > 0.001}>
      <group position={[target.positionWorld.x, target.positionWorld.y, target.positionWorld.z + 0.66]}>
        <mesh>
          <torusGeometry args={[0.34, 0.025, 8, 32]} />
          <meshBasicMaterial color={palette.red} />
        </mesh>
        <mesh>
          <torusGeometry args={[0.1, 0.018, 8, 24]} />
          <meshBasicMaterial color={palette.red} />
        </mesh>
        <mesh scale={[1.25, 0.025, 0.025]}>
          <boxGeometry />
          <meshBasicMaterial color={palette.red} />
        </mesh>
        <mesh scale={[0.025, 1.25, 0.025]}>
          <boxGeometry />
          <meshBasicMaterial color={palette.red} />
        </mesh>
      </group>
      <group position={[markerX, target.positionWorld.y, target.positionWorld.z + 0.58]}>
        <mesh castShadow>
          <boxGeometry args={[1.05, 2.2, 0.16]} />
          <meshStandardMaterial color={palette.red} roughness={0.72} />
        </mesh>
        {[0.55, 0.2, -0.15, -0.5].map((y, index) => (
          <mesh key={y} position={[-0.08, y, 0.1]}>
            <boxGeometry args={[index === 3 ? 0.55 : 0.7, 0.055, 0.02]} />
            <meshBasicMaterial color={palette.paper} />
          </mesh>
        ))}
      </group>
    </group>
  );
}

function InspectionTable(props: Omit<InstrumentSceneProps, "onPerformance" | "playing">) {
  const objectById = useMemo(
    () => new Map(props.manifest.objects.map((object) => [object.id, object])),
    [props.manifest.objects],
  );
  return (
    <group rotation={[-0.02, -0.035, -0.015]}>
      <mesh position={[0, 0, -0.42]}>
        <boxGeometry args={[13.2, 8.55, 0.28]} />
        <meshStandardMaterial color={palette.board} roughness={0.88} />
      </mesh>
      {([
        [-6.25, -3.85],
        [6.25, -3.85],
        [-6.25, 3.85],
        [6.25, 3.85],
      ] as Array<[number, number]>).map(([x, y]) => (
        <mesh key={`${x}:${y}`} position={[x, y, -0.22]} rotation={[Math.PI / 2, 0, 0]}>
          <cylinderGeometry args={[0.075, 0.075, 0.07, 12]} />
          <meshStandardMaterial color={palette.brass} metalness={0.72} roughness={0.3} />
        </mesh>
      ))}
      {props.manifest.objects.map((object) => (
        <SceneObjectPart
          key={object.id}
          object={object}
          channels={props.channels}
          mode={props.mode}
          selectedId={props.selectedId}
          isolatedId={props.isolatedId}
          instant={props.channels.finding === 1}
          onSelect={props.onSelect}
        />
      ))}
      {props.manifest.connections.map((connection) => (
        <Connection
          key={connection.id}
          connection={connection}
          objectById={objectById}
          channels={props.channels}
          selected={props.selectedId === connection.id}
          isolated={props.isolatedId !== null && props.isolatedId !== connection.id}
          onSelect={props.onSelect}
        />
      ))}
      <RegistrationReticle manifest={props.manifest} channels={props.channels} />
    </group>
  );
}

export function InstrumentScene(props: InstrumentSceneProps) {
  return (
    <Canvas
      aria-hidden="true"
      camera={{ fov: 34, near: 0.1, far: 100 }}
      dpr={[0.75, 1]}
      frameloop={props.playing ? "always" : "demand"}
      gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
      onPointerMissed={() => undefined}
    >
      <color attach="background" args={[palette.paper]} />
      <ambientLight intensity={1.7} />
      <directionalLight position={[4, 7, 11]} intensity={2.5} />
      <directionalLight position={[-6, -2, 8]} intensity={0.65} color="#a5c1c4" />
      <CameraRig />
      <InspectionTable
        manifest={props.manifest}
        channels={props.channels}
        mode={props.mode}
        selectedId={props.selectedId}
        isolatedId={props.isolatedId}
        onSelect={props.onSelect}
      />
      <PerformanceProbe onPerformance={props.onPerformance} />
    </Canvas>
  );
}
