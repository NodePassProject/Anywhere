//
//  DIQRScannerView.swift
//  Anywhere
//
//  Created by Argsment Limited on 2/16/26.
//

import SwiftUI
import AVFoundation

fileprivate struct CameraProperties {
    var session: AVCaptureSession = .init()
    var output: AVCaptureMetadataOutput = .init()
    var scannedCode: String?
    var permissionState: Permission?
    
    enum Permission: String {
        case idle = "Not Determined"
        case approved = "Access Granted"
        case denied = "Access Denied"
    }
    
    static func checkAndAskCameraPermission() async -> Permission? {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: return Permission.approved
        case .notDetermined:
            /// Requesting Camera Access
            if await AVCaptureDevice.requestAccess(for: .video) {
                /// Permission Granted
                return Permission.approved
            } else {
                /// Permission Denied
                return Permission.denied
            }
        case .denied, .restricted: return Permission.denied
        default: return nil
        }
    }
}

extension View {
    @ViewBuilder
    func qrScanner(isScanning: Binding<Bool>, onScan: @escaping (String) -> Void) -> some View {
        self
            .modifier(QRScannerViewModifier(isScanning: isScanning, onScan: onScan))
    }
}

fileprivate struct QRScannerViewModifier: ViewModifier {
    @Binding var isScanning: Bool
    var onScan: (String) -> Void
    /// Modifier Properties
    @State private var showFullScreenCover: Bool = false
    func body(content: Content) -> some View {
        content
            .fullScreenCover(isPresented: $showFullScreenCover) {
                DIQRScannerView {
                    isScanning = false
                    Task { @MainActor in
                        showFullScreenCoverWithoutAnimation(false)
                    }
                } onScan: { code in
                    onScan(code)
                }
                .presentationBackground(.clear)
            }
            .onChange(of: isScanning) { oldValue, newValue in
                if newValue {
                    showFullScreenCoverWithoutAnimation(true)
                }
            }
    }
    
    private func showFullScreenCoverWithoutAnimation(_ status: Bool) {
        var transaction = Transaction()
        transaction.disablesAnimations = true
        withTransaction(transaction) {
            showFullScreenCover = status
        }
    }
}

fileprivate struct DIQRScannerView: View {
    var onClose: () -> ()
    var onScan: (String) -> Void
    /// View Properties
    @State private var isInitialized: Bool = false
    @State private var showContent: Bool = false
    @State private var isExpanding: Bool = false
    @State private var camera: CameraProperties = .init()
    @Environment(\.openURL) private var openURL
    var body: some View {
        GeometryReader {
            let size = $0.size
            let safeArea = $0.safeAreaInsets
            
            /// Dynamic Island
            let haveDynamicIsland: Bool = safeArea.top >= 59
            let dynamicIslandWidth: CGFloat = 120
            let dynamicIslandHeight: CGFloat = 36
            let topOffset: CGFloat = haveDynamicIsland ? (11 + max((safeArea.top - 59), 0)) : (isExpanding ? safeArea.top : -50)
            
            let expandedWidth: CGFloat = size.width - 30
            /// For making it square
            let expandedHeight: CGFloat = min(size.height, expandedWidth)
            
            ZStack(alignment: .top) {
                Rectangle()
                    .fill(.ultraThinMaterial)
                    .contentShape(.rect)
                    .opacity(isExpanding ? 1 : 0)
                    .onTapGesture {
                        toggle(false)
                    }
                
                /// Scanner Animated View
                if showContent {
                    RoundedRectangle(cornerRadius: 30)
                        .fill(.black)
                        .overlay {
                            GeometryReader {
                                let cameraSize = $0.size
                                
                                ScannerView(cameraSize)
                            }
                            .overlay(alignment: .bottom) {
                                /// Your Custom Text
                                Text("Scan your QR code")
                                    .font(.caption2)
                                    .foregroundStyle(.white.secondary)
                                    .lineLimit(1)
                                    .fixedSize()
                                    .offset(y: 25)
                            }
                            .padding(80)
                            .compositingGroup()
                            .blur(radius: isExpanding ? 0 : 15)
                            .opacity(isExpanding ? 1 : 0)
                            .geometryGroup()
                        }
                        .overlay {
                            PermissionDeniedView()
                        }
                        .frame(
                            width: isExpanding ? expandedWidth : dynamicIslandWidth,
                            height: isExpanding ? expandedHeight : dynamicIslandHeight
                        )
                        .offset(y: topOffset)
                        .background {
                            if isExpanding {
                                Rectangle()
                                    .fill(.clear)
                                    .onDisappear {
                                        showContent = false
                                    }
                            }
                        }
                        .transition(.identity)
                        .onDisappear {
                            onClose()
                        }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .ignoresSafeArea()
            .task {
                guard !isInitialized else { return }
                isInitialized = true
                showContent = true
                try? await Task.sleep(for: .seconds(0.05))
                toggle(true)
                camera.permissionState = await CameraProperties.checkAndAskCameraPermission()
            }
            .onChange(of: camera.scannedCode) { oldValue, newValue in
                if let newValue {
                    onScan(newValue)
                    toggle(false)
                }
            }
        }
        .statusBarHidden()
    }
    
    /// Scanner View
    @ViewBuilder
    private func ScannerView(_ size: CGSize) -> some View {
        let shape = RoundedRectangle(cornerRadius: 40, style: .continuous)
        
        ZStack {
            /// Camera AVSessionLayer View!
            if let permissionState = camera.permissionState {
                if permissionState == .approved {
                    CameraLayerView(size: size, camera: $camera)
                }
            }
            
            shape
                .stroke(.gray, lineWidth: 2)
        }
        .frame(width: size.width, height: size.height)
        .clipShape(shape)
    }
    
    /// Permission Denied View
    @ViewBuilder
    private func PermissionDeniedView() -> some View {
        /// Showing Info with Setting url to change the camera settings!
        VStack(spacing: 4) {
            Image(systemName: "camera.viewfinder")
                .font(.system(size: 45))
                .foregroundStyle(.white)

            Text("Permission denied")
                .font(.caption)
                .foregroundStyle(.red)
            
            if let settingsURL = URL(string: UIApplication.openSettingsURLString) {
                Button("Go to Settings") {
                    openURL(settingsURL)
                }
                .font(.caption)
                .foregroundStyle(.white)
                .underline()
            }
        }
        .fixedSize()
        .compositingGroup()
        .opacity(camera.permissionState == .denied ? 1 : 0)
        .blur(radius: isExpanding ? 0 : 15)
        .opacity(isExpanding ? 1 : 0)
    }
    
    private func toggle(_ status: Bool) {
        withAnimation(.interpolatingSpring(duration: 0.35, bounce: 0, initialVelocity: 0)) {
            isExpanding = status
        }
        
        if !status {
            /// Stopping session safely
            DispatchQueue.global(qos: .background).async {
                camera.session.stopRunning()
            }
        }
    }
}

fileprivate struct CameraLayerView: UIViewRepresentable {
    var size: CGSize
    @Binding var camera: CameraProperties
    func makeUIView(context: Context) -> UIView {
        let view = UIView(frame: .init(origin: .zero, size: size))
        view.backgroundColor = .clear
        
        /// Setting up camera layer
        let layer = AVCaptureVideoPreviewLayer(session: camera.session)
        layer.frame = .init(origin: .zero, size: size)
        layer.videoGravity = .resizeAspectFill
        layer.masksToBounds = true
        view.layer.addSublayer(layer)
        
        return view
    }
    
    func updateUIView(_ uiView: UIView, context: Context) {
        
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }
    
    class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        var parent: CameraLayerView
        init(parent: CameraLayerView) {
            self.parent = parent
            super.init()
            Task {
                setupCamera()
            }
        }
        
        func setupCamera() {
            do {
                let session = parent.camera.session
                let output = parent.camera.output
                
                guard !session.isRunning else { return }
                /// Finding Back Camera
                guard let device = AVCaptureDevice.DiscoverySession(deviceTypes: [.builtInWideAngleCamera], mediaType: .video, position: .back).devices.first else {
                    return
                }
                
                /// Camera Input
                let input = try AVCaptureDeviceInput(device: device)
                /// Checking whether input & output can be added to the session
                guard session.canAddInput(input), session.canAddOutput(output) else {
                    return
                }
                
                /// Adding input & output to camera session
                session.beginConfiguration()
                session.addInput(input)
                session.addOutput(output)
                /// Setting output configuration to read QR codes
                output.metadataObjectTypes = [.qr]
                /// Adding delegate to retrieve the scanned QR code
                output.setMetadataObjectsDelegate(self, queue: .main)
                session.commitConfiguration()
                /// Starting Session
                /// NOTE: Session must be started in background thread
                DispatchQueue.global(qos: .background).async {
                    session.startRunning()
                }
            } catch {
                print(error.localizedDescription)
            }
        }
        
        func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
            /// FETCH QR CODE
            if let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject, let code = object.stringValue {
                /// One Time Update
                guard parent.camera.scannedCode == nil else { return }
                parent.camera.scannedCode = code
                AudioServicesPlaySystemSound(SystemSoundID(kSystemSoundID_Vibrate))
            }
        }
    }
}
